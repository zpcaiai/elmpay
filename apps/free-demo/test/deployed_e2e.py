"""Real HTTPS demo integration checks; never print checkout bearer credentials."""
import json
import http.client
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def open_verified_request(opener, req, label):
    """Retry only transport errors, reusing the exact request and idempotency key."""
    for attempt in range(3):
        try:
            return opener.open(req, timeout=60)
        except urllib.error.HTTPError:
            raise
        except (urllib.error.URLError, ConnectionError, TimeoutError, ssl.SSLError,
                http.client.RemoteDisconnected) as error:
            if attempt == 2:
                raise
            print(json.dumps({"transport_retry": label, "attempt": attempt + 1,
                              "error_type": type(error).__name__, "same_request": True}), flush=True)


def run(origin):
    if origin not in {"https://elmpay.onrender.com", "https://elmpay.vercel.app"}:
        raise ValueError("only the explicitly authorized demo origins are supported")
    opener = urllib.request.build_opener(NoRedirect)
    results = []

    def request(label, path, expected, body=None, token=None, key=None, source=None, header_overrides=None):
        headers = {"accept": "application/json"}
        if body is not None:
            headers.update({"content-type": "application/json", "origin": source or origin})
        if token:
            headers["authorization"] = "CheckoutSession " + token
        if key:
            headers["idempotency-key"] = key
        headers.update(header_overrides or {})
        req = urllib.request.Request(origin + path, headers=headers,
                                     data=None if body is None else json.dumps(body).encode())
        try:
            response = open_verified_request(opener, req, label)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            raw = response.read(65537)
            assert len(raw) <= 65536, label + ": response too large"
            assert response.code == expected, f"{label}: HTTP {response.code}, expected {expected}"
            assert response.headers.get("x-elmpay-demo") == "true", label + ": demo header missing"
            assert "no-store" in response.headers.get("cache-control", ""), label + ": caching enabled"
            assert response.headers.get("referrer-policy") == "no-referrer", label + ": referrer unsafe"
            content_type = response.headers.get("content-type", "")
            if "application/json" in content_type:
                value = json.loads(raw)
                assert value["demo"] is True and value["real_payments"] is False
            else:
                value = raw.decode()
                assert "frame-ancestors 'none'" in response.headers.get("content-security-policy", "")
            results.append({"check": label, "http_status": response.code, "pass": True,
                            **({"state": value["status"]} if isinstance(value, dict) and "status" in value else {})})
            print(json.dumps(results[-1]), flush=True)
            return value

    ready = request("real gateway readiness", "/health/ready", 200)
    assert ready["status"] == "DEMO_READY" and ready["provider"] == "local-sandbox"
    page = request("visible demo boundary", "/", 200)
    assert "真实支付已禁用" in page and "不发生真实扣款" in page and "内存" in page
    request("admin route denied", "/v1/payment_intents", 404)
    request("untrusted origin denied", "/demo/orders", 403, {"scenario": "succeeded"},
            key="demo-" + str(uuid.uuid4()), source="https://untrusted.example")
    request("amount injection denied", "/demo/orders", 400, {"scenario": "succeeded", "amount": 1},
            key="demo-" + str(uuid.uuid4()))
    request("browser checkout page", "/checkout", 200)
    request("order collection requires POST", "/demo/orders", 405)
    request("query injection denied", "/demo/orders?scenario=succeeded", 400)
    request("unsupported live scenario denied", "/demo/orders", 400, {"scenario": "live"},
            key="demo-" + str(uuid.uuid4()))
    request("missing idempotency key denied", "/demo/orders", 400, {"scenario": "succeeded"})
    request("non JSON creation denied", "/demo/orders", 415, {"scenario": "succeeded"},
            key="demo-" + str(uuid.uuid4()), header_overrides={"content-type": "text/plain"})
    request("merchant checkout API denied", "/v1/checkout-sessions", 404)
    for unsupported in ["wechat_jsapi", "__proto__", None]:
        request("unsupported demo method denied", "/demo/orders", 400,
                {"scenario": "unknown", "payment_method": unsupported}, key="demo-" + str(uuid.uuid4()))
    request("WeChat currency injection denied", "/demo/orders", 400,
            {"scenario": "unknown", "payment_method": "wechat_native", "currency": "USD"},
            key="demo-" + str(uuid.uuid4()))
    cases = [(method, currency, scenario, state)
             for method, currency in [("card", "USD"), ("wechat_native", "CNY")]
             for scenario, state in [("succeeded", "SUCCEEDED"), ("declined", "FAILED"),
                                     ("unknown", "PENDING"), ("authorized", "PENDING"),
                                     ("requires_action", "PENDING")]]
    for method, currency, scenario, expected_state in cases:
        label = method + " " + scenario
        other_method = "card" if method == "wechat_native" else "wechat_native"
        create_body = {"scenario": scenario, **({"payment_method": method} if method != "card" else {})}
        key = "demo-" + str(uuid.uuid4())
        created = request(label + " create", "/demo/orders", 201, create_body, key=key)
        assert created["payment_method"] == method and created["currency"] == currency and created["amount"] == 1000
        assert created["simulation_engine"] == "local-sandbox"
        replay = request(label + " create replay", "/demo/orders", 201, create_body, key=key)
        assert replay["checkout_session_id"] == created["checkout_session_id"]
        assert replay["checkout_url"] == created["checkout_url"]
        request(label + " create conflict", "/demo/orders", 409,
                {**create_body, "scenario": "unknown" if scenario != "unknown" else "succeeded"}, key=key)
        request(label + " profile key conflict", "/demo/orders", 409,
                {**create_body, "payment_method": other_method}, key=key)
        checkout = urllib.parse.urlsplit(created["checkout_url"])
        assert checkout.scheme == "https" and checkout.netloc == "elmpay.vercel.app"
        assert checkout.path == "/checkout" and not checkout.query
        fragment = urllib.parse.parse_qs(checkout.fragment)
        session = created["checkout_session_id"]
        assert fragment["session"] == [session]
        token = fragment["token"][0]
        path = "/api/checkout/sessions/" + session
        request(label + " missing bearer denied", path, 401)
        changed = ("A" if token[0] != "A" else "B") + token[1:]
        request(label + " tampered bearer denied", path, 401, token=changed)
        view = request(label + " initial state", path, 200, token=token)
        assert view["status"] == "OPEN" and view["checkoutSessionId"] == session
        # The browser API intentionally exposes formatted money, not the
        # merchant API's raw amount/currency fields. Validate its exact contract.
        expected_display = {"CNY": {"¥10.00", "￥10.00"}, "USD": {"US$10.00", "$10.00"}}[currency]
        assert view["displayAmount"] in expected_display, label + ": incorrect server money display"
        assert len(view["methods"]) == 1 and view["methods"][0]["id"] == method and view["methods"][0]["eligible"]
        assert "10.00" in view["displayAmount"]
        if currency == "CNY":
            assert "$" not in view["displayAmount"] and "USD" not in view["displayAmount"]
        confirm_key = "demo-confirm-" + str(uuid.uuid4())
        command = {"method": method, "payment_method_reference": "psp://elmpay-demo/" + session,
                   "provider_parameters": {"simulation": scenario}}
        request(label + " session method mismatch denied", path + "/confirm", 400,
                {**command, "method": other_method}, token=token, key="demo-wrong-" + str(uuid.uuid4()))
        request(label + " real provider reference denied", path + "/confirm", 400,
                {**command, "payment_method_reference": "psp://stripe/not-a-real-token"},
                token=token, key=confirm_key)
        confirmed = request(label + " confirm", path + "/confirm", 200, command,
                            token=token, key=confirm_key)
        assert confirmed["status"] == expected_state, scenario + ": incorrect authoritative state"
        assert not any(m["eligible"] for m in confirmed["methods"]), scenario + ": confirmation still enabled"
        if scenario == "requires_action":
            assert confirmed["nextAction"].get("action") == "local_challenge"
        # Captured intents reject a second confirmation; declined/unknown attempts
        # keep the core intent OPEN and replay by the same key without redispatch.
        replay = request(label + " repeat confirmation", path + "/confirm",
                         200 if scenario in {"declined", "unknown"} else 400, command,
                         token=token, key=confirm_key)
        if scenario in {"declined", "unknown"}:
            assert replay["status"] == expected_state
            assert replay["gateway_status"] == "OPEN"
            assert replay["demo_provider_result"] == "local_" + scenario
        final = request(label + " authoritative reread", path, 200, token=token)
        assert final["status"] == expected_state
        assert final["displayAmount"] in expected_display
        assert len(final["methods"]) == 1 and final["methods"][0]["id"] == method
    print(json.dumps({"result": "PASS", "origin": origin, "checks": len(results),
                      "executed": True, "pid": os.getpid(), "real_payments": False}), flush=True)


if __name__ == "__main__":
    run(sys.argv[1])
