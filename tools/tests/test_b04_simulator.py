"""B04 / AT-B04-01 — the offline provider simulator actually runs.

These are not mocks of a mock: the simulator is started on a real socket and
driven over HTTP, so the idempotency and signature behaviours the platform will
depend on are demonstrated before any connector exists.
"""
from __future__ import annotations

import json
import threading
import unittest
import urllib.error
import urllib.request

from tools.simulator.provider_sim import (
    SimulatorConfig,
    SimulatorRefused,
    make_server,
    reject_card_data,
    sign,
    verify,
)


class RunningSimulator:
    def __init__(self, provider: str = "wechat", secret: str = "sim-secret-test") -> None:
        self.server = make_server(SimulatorConfig(provider=provider, secret=secret))
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.port}{path}"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def request(url: str, method: str = "GET", body: dict | None = None,
            headers: dict | None = None) -> tuple[int, dict]:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


class SimulatorLifecycle(unittest.TestCase):
    def setUp(self) -> None:
        self.sim = RunningSimulator()
        self.addCleanup(self.sim.close)

    def test_health_declares_synthetic_data(self):
        status, body = request(self.sim.url("/healthz"))
        self.assertEqual(status, 200)
        self.assertEqual(body["mode"], "simulator")
        self.assertEqual(body["data"], "synthetic")

    def test_create_payment_requires_idempotency_key(self):
        status, body = request(self.sim.url("/payments"), "POST",
                               {"amount_minor": 1999, "currency": "CNY"})
        self.assertEqual(status, 400)
        self.assertEqual(body["error"], "idempotency_key_required")

    def test_same_key_same_payload_returns_first_result(self):
        payload = {"amount_minor": 1999, "currency": "CNY"}
        headers = {"Idempotency-Key": "key-1"}
        first = request(self.sim.url("/payments"), "POST", payload, headers)
        second = request(self.sim.url("/payments"), "POST", payload, headers)
        self.assertEqual(first[0], 201)
        self.assertEqual(second[0], 200)
        self.assertEqual(first[1]["payment_id"], second[1]["payment_id"])

    def test_same_key_different_payload_is_a_conflict(self):
        headers = {"Idempotency-Key": "key-2"}
        request(self.sim.url("/payments"), "POST",
                {"amount_minor": 1999, "currency": "CNY"}, headers)
        status, body = request(self.sim.url("/payments"), "POST",
                               {"amount_minor": 999999, "currency": "CNY"}, headers)
        self.assertEqual(status, 409)
        self.assertEqual(body["error"], "idempotency_key_reuse_with_different_payload")

    def test_concurrent_replays_produce_exactly_one_payment(self):
        payload = {"amount_minor": 500, "currency": "CNY"}
        headers = {"Idempotency-Key": "race-key"}
        results: list[tuple[int, dict]] = []
        lock = threading.Lock()

        def worker():
            result = request(self.sim.url("/payments"), "POST", payload, headers)
            with lock:
                results.append(result)

        threads = [threading.Thread(target=worker) for _ in range(16)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(len(results), 16)
        ids = {body["payment_id"] for _, body in results}
        self.assertEqual(len(ids), 1, ids)
        self.assertEqual(sum(1 for status, _ in results if status == 201), 1)

    def test_created_payment_is_queryable(self):
        _, created = request(self.sim.url("/payments"), "POST",
                             {"amount_minor": 100, "currency": "CNY"},
                             {"Idempotency-Key": "key-3"})
        status, fetched = request(self.sim.url(f"/payments/{created['payment_id']}"))
        self.assertEqual(status, 200)
        self.assertTrue(fetched["synthetic"])

    def test_unknown_payment_is_not_found(self):
        status, _ = request(self.sim.url("/payments/does-not-exist"))
        self.assertEqual(status, 404)

    def test_card_number_shaped_payload_is_rejected(self):
        status, body = request(self.sim.url("/payments"), "POST",
                               {"amount_minor": 100, "currency": "USD",
                                "note": "4242424242424242"},
                               {"Idempotency-Key": "key-4"})
        self.assertEqual(status, 422)
        self.assertEqual(body["error"], "card_data_rejected")


class SimulatorSignatures(unittest.TestCase):
    def setUp(self) -> None:
        self.sim = RunningSimulator(secret="sim-secret-callback")
        self.addCleanup(self.sim.close)

    def test_callback_signature_verifies(self):
        status, envelope = request(self.sim.url("/_sim/callback"), "POST",
                                   {"event": "payment.succeeded", "amount_minor": 100})
        self.assertEqual(status, 200)
        self.assertTrue(verify("sim-secret-callback", envelope["timestamp"], envelope["nonce"],
                               envelope["body"], envelope["signature"]))

    def test_tampered_body_fails_verification(self):
        _, envelope = request(self.sim.url("/_sim/callback"), "POST",
                              {"event": "payment.succeeded", "amount_minor": 100})
        tampered = envelope["body"].replace("100", "1000000")
        self.assertFalse(verify("sim-secret-callback", envelope["timestamp"], envelope["nonce"],
                                tampered, envelope["signature"]))

    def test_wrong_secret_fails_verification(self):
        _, envelope = request(self.sim.url("/_sim/callback"), "POST", {"event": "x"})
        self.assertFalse(verify("sim-secret-other", envelope["timestamp"], envelope["nonce"],
                                envelope["body"], envelope["signature"]))

    def test_stale_timestamp_fails_verification(self):
        _, envelope = request(self.sim.url("/_sim/callback"), "POST", {"event": "x"})
        stale = float(envelope["timestamp"]) + 10_000
        self.assertFalse(verify("sim-secret-callback", envelope["timestamp"], envelope["nonce"],
                                envelope["body"], envelope["signature"], now=stale))

    def test_signature_is_deterministic(self):
        first = sign("sim-secret-callback", "1000", "abc", "{}")
        second = sign("sim-secret-callback", "1000", "abc", "{}")
        self.assertEqual(first, second)


class SimulatorRefusesUnsafeConfiguration(unittest.TestCase):
    def test_refuses_non_synthetic_secret(self):
        with self.assertRaises(SimulatorRefused):
            make_server(SimulatorConfig(provider="stripe", secret="sk_live_realkey0000"))

    def test_refuses_production_marker_in_merchant_id(self):
        with self.assertRaises(SimulatorRefused):
            make_server(SimulatorConfig(provider="alipay", secret="sim-ok",
                                        merchant_id="prod-merchant-1"))

    def test_refuses_unknown_provider(self):
        with self.assertRaises(SimulatorRefused):
            make_server(SimulatorConfig(provider="unionpay", secret="sim-ok"))

    def test_card_data_guard_accepts_non_card_digits(self):
        reject_card_data({"amount_minor": 4242424242424242 // 1000, "note": "order 12345"})

    def test_card_data_guard_rejects_valid_luhn(self):
        with self.assertRaises(SimulatorRefused):
            reject_card_data({"note": "5555 5555 5555 4444"})
