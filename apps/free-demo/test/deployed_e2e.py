"""Real HTTPS demo integration checks; never print checkout bearer credentials."""
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def run(origin):
    if origin not in {"https://elmpay.onrender.com", "https://elmpay.vercel.app"}:
        raise ValueError("only the explicitly authorized demo origins are supported")
    opener = urllib.request.build_opener(NoRedirect)
    results = []

    def request(label, path, expected, body=None, token=None, key=None, source=None):
        headers = {"accept": "application/json"}
        if body is not None:
            headers.update({"content-type": "application/json", "origin": source or origin})
        if token:
            headers["authorization"] = "CheckoutSession " + token
        if key:
            headers["idempotency-key"] = key
        req = urllib.request.Request(origin + path, headers=headers,
                                     data=None if body is None else json.dumps(body).encode())
        try:
            response = opener.open(req, timeout=60)
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
    for scenario, expected_state in [("succeeded", "SUCCEEDED"), ("declined", "FAILED"), ("unknown", "PENDING")]:
        key = "demo-" + str(uuid.uuid4())
        created = request(scenario + " create", "/demo/orders", 201, {"scenario": scenario}, key=key)
        replay = request(scenario + " create replay", "/demo/orders", 201, {"scenario": scenario}, key=key)
        assert replay["checkout_session_id"] == created["checkout_session_id"]
        assert replay["checkout_url"] == created["checkout_url"]
        request(scenario + " create conflict", "/demo/orders", 409,
                {"scenario": "unknown" if scenario != "unknown" else "succeeded"}, key=key)
        checkout = urllib.parse.urlsplit(created["checkout_url"])
        assert checkout.scheme == "https" and checkout.netloc == "elmpay.vercel.app"
        assert checkout.path == "/checkout" and not checkout.query
        fragment = urllib.parse.parse_qs(checkout.fragment)
        session = created["checkout_session_id"]
        assert fragment["session"] == [session]
        token = fragment["token"][0]
        path = "/api/checkout/sessions/" + session
        request(scenario + " missing bearer denied", path, 401)
        changed = ("A" if token[0] != "A" else "B") + token[1:]
        request(scenario + " tampered bearer denied", path, 401, token=changed)
        view = request(scenario + " initial state", path, 200, token=token)
        assert view["status"] == "OPEN" and view["checkoutSessionId"] == session
        assert any(m["id"] == "card" and m["eligible"] for m in view["methods"])
        confirm_key = "demo-confirm-" + str(uuid.uuid4())
        command = {"method": "card", "payment_method_reference": "psp://elmpay-demo/" + session,
                   "provider_parameters": {"simulation": scenario}}
        request(scenario + " real provider reference denied", path + "/confirm", 400,
                {**command, "payment_method_reference": "psp://stripe/not-a-real-token"},
                token=token, key=confirm_key)
        confirmed = request(scenario + " confirm", path + "/confirm", 200, command,
                            token=token, key=confirm_key)
        assert confirmed["status"] == expected_state, scenario + ": incorrect authoritative state"
        # Captured intents reject a second confirmation; declined/unknown attempts
        # keep the core intent OPEN and replay by the same key without redispatch.
        replay = request(scenario + " repeat confirmation", path + "/confirm",
                         400 if scenario == "succeeded" else 200, command,
                         token=token, key=confirm_key)
        if scenario != "succeeded":
            assert replay["status"] == expected_state
            assert replay["gateway_status"] == "OPEN"
            assert replay["demo_provider_result"] == "local_" + scenario
        final = request(scenario + " authoritative reread", path, 200, token=token)
        assert final["status"] == expected_state
    print(json.dumps({"result": "PASS", "origin": origin, "checks": len(results),
                      "executed": True, "pid": os.getpid(), "real_payments": False}), flush=True)


if __name__ == "__main__":
    run(sys.argv[1])
