#!/usr/bin/env python3
"""Runtime smoke test for the offline provider simulators.

Starts every declared simulator on an ephemeral port and drives it over real
HTTP. This is the runtime evidence that the local platform's provider stubs
work without network access, and that the two behaviours the platform depends
on — idempotency and signature verification — hold in a running process.
"""
from __future__ import annotations

import json
import sys
import threading
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.simulator.provider_sim import (  # noqa: E402
    SimulatorConfig,
    SimulatorRefused,
    make_server,
    verify,
)

SECRET = "sim-smoke-secret"


def call(url: str, method: str = "GET", body: dict | None = None,
         headers: dict | None = None) -> tuple[int, dict]:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def smoke(provider: str) -> list[str]:
    failures: list[str] = []
    server = make_server(SimulatorConfig(provider=provider, secret=SECRET))
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{port}"
    try:
        status, body = call(f"{base}/healthz")
        if status != 200 or body.get("data") != "synthetic":
            failures.append(f"{provider}: health check")
        print(f"  [{provider}] /healthz -> {status} {body}")

        payload = {"amount_minor": 1234, "currency": "CNY"}
        headers = {"Idempotency-Key": f"{provider}-smoke"}
        first = call(f"{base}/payments", "POST", payload, headers)
        replay = call(f"{base}/payments", "POST", payload, headers)
        conflict = call(f"{base}/payments", "POST", {**payload, "amount_minor": 1}, headers)
        print(f"  [{provider}] create={first[0]} replay={replay[0]} conflict={conflict[0]}")
        if first[0] != 201 or replay[0] != 200 or conflict[0] != 409:
            failures.append(f"{provider}: idempotency")
        if first[1]["payment_id"] != replay[1]["payment_id"]:
            failures.append(f"{provider}: replay returned a different payment")

        missing_key = call(f"{base}/payments", "POST", payload)
        if missing_key[0] != 400:
            failures.append(f"{provider}: missing idempotency key was accepted")

        card = call(f"{base}/payments", "POST", {**payload, "note": "4242424242424242"},
                    {"Idempotency-Key": f"{provider}-card"})
        print(f"  [{provider}] card-shaped payload -> {card[0]}")
        if card[0] != 422:
            failures.append(f"{provider}: card-shaped payload was accepted")

        _, envelope = call(f"{base}/_sim/callback", "POST", {"event": "payment.succeeded"})
        good = verify(SECRET, envelope["timestamp"], envelope["nonce"],
                      envelope["body"], envelope["signature"])
        tampered = verify(SECRET, envelope["timestamp"], envelope["nonce"],
                          envelope["body"] + " ", envelope["signature"])
        print(f"  [{provider}] callback signature valid={good} tampered_accepted={tampered}")
        if not good or tampered:
            failures.append(f"{provider}: callback signature verification")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    return failures


def main() -> int:
    declaration = json.loads((ROOT / "governance/dev-platform.json").read_text("utf-8"))
    providers = [s["provider"] for s in declaration["simulators"]]
    failures: list[str] = []
    for provider in providers:
        print(f"simulator: {provider}")
        failures += smoke(provider)

    print("\nrefusal checks")
    for label, config in (
        ("non-synthetic secret", SimulatorConfig(provider="stripe", secret="sk_live_x")),
        ("production merchant id", SimulatorConfig(provider="alipay", secret="sim-ok",
                                                   merchant_id="prod-1")),
        ("unknown provider", SimulatorConfig(provider="unionpay", secret="sim-ok")),
    ):
        try:
            make_server(config).server_close()
            print(f"  [FAIL] {label}: simulator started anyway")
            failures.append(f"refusal: {label}")
        except SimulatorRefused as exc:
            print(f"  [OK ] {label}: refused ({exc})")

    print(f"\nproviders={len(providers)} failures={len(failures)}")
    for failure in failures:
        print(f"  FAILURE: {failure}")
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
