#!/usr/bin/env python3
"""Execute every synthetic B40-B55 provider/channel/operation contract over real HTTP."""
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
    CONTRACT_FAILURES,
    PROVIDER_CHANNELS,
    PROVIDER_OPERATIONS,
    SimulatorConfig,
    make_server,
)

MATRIX = ROOT / "contracts/provider/local-simulator-matrix.json"


def call(url: str, body: dict, key: str) -> tuple[int, dict]:
    request = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"), method="POST",
                                     headers={"Content-Type": "application/json",
                                              "Idempotency-Key": key})
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read().decode("utf-8"))


def payload(provider: str, operation: str, channel: str, *, inject: str | None = None) -> dict:
    value: dict[str, object] = {
        "operation": operation,
        "channel": channel,
        "amount_minor": 1250,
        "currency": "USD" if provider not in {"wechat", "alipay"} else "CNY",
    }
    if inject is not None:
        value["inject"] = inject
    if provider == "wechat":
        value.update({"openid": "openid_synthetic_001", "client_ip": "127.0.0.1",
                      "h5_type": "Wap", "description": "synthetic"})
    elif provider == "alipay":
        value.update({"store_id": "store_synthetic_001", "subject": "synthetic"})
    elif provider == "stripe":
        value["payment_method_reference"] = "pm_synthetic_001"
    elif provider == "paypal":
        value.update({"return_route_id": "route_synthetic_return",
                      "cancel_route_id": "route_synthetic_cancel"})
    elif provider == "apple_pay":
        value.update({"domain": "pay.synthetic.example", "device_has_wallet": True,
                      "psp": "stripe", "opaque_token_reference": "tok_synthetic_001"})
    return value


def verify_declaration() -> dict:
    declaration = json.loads(MATRIX.read_text("utf-8"))
    if declaration.get("data_classification") != "synthetic_only":
        raise AssertionError("provider contract matrix must remain synthetic-only")
    if declaration.get("certification", {}).get("official_provider_certification") != "BLOCKED_EXTERNAL":
        raise AssertionError("local contracts must not claim official certification")
    providers = declaration.get("providers")
    if set(providers) != set(PROVIDER_CHANNELS):
        raise AssertionError("provider declaration differs from executable simulator")
    for provider, configured in providers.items():
        if tuple(configured["channels"]) != PROVIDER_CHANNELS[provider]:
            raise AssertionError(f"{provider} channel declaration differs from code")
        if tuple(configured["operations"]) != PROVIDER_OPERATIONS[provider]:
            raise AssertionError(f"{provider} operation declaration differs from code")
    if tuple(declaration.get("failure_modes", ())) != CONTRACT_FAILURES:
        raise AssertionError("failure declaration differs from executable simulator")
    return declaration


def run_provider(provider: str) -> tuple[int, list[str]]:
    server = make_server(SimulatorConfig(provider=provider, secret="sim-contract-secret"))
    thread = threading.Thread(target=server.serve_forever,
                              kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    endpoint = f"http://127.0.0.1:{server.server_address[1]}/_sim/contract"
    failures: list[str] = []
    vectors = 0
    try:
        for channel in PROVIDER_CHANNELS[provider]:
            for operation in PROVIDER_OPERATIONS[provider]:
                vectors += 1
                key = f"contract-{provider}-{vectors:08d}"
                request = payload(provider, operation, channel)
                first = call(endpoint, request, key)
                replay = call(endpoint, request, key)
                conflict = call(endpoint, {**request, "amount_minor": 1251}, key)
                if first[0] != 201 or replay[0] != 200 or conflict[0] != 409:
                    failures.append(f"{provider}/{channel}/{operation}: idempotency")
                if first[1] != replay[1] or not first[1].get("synthetic"):
                    failures.append(f"{provider}/{channel}/{operation}: deterministic replay")

        for index, injection in enumerate(CONTRACT_FAILURES, 1):
            request = payload(provider, PROVIDER_OPERATIONS[provider][0],
                              PROVIDER_CHANNELS[provider][0], inject=injection)
            status, result = call(endpoint, request, f"failure-{provider}-{index:08d}")
            if status != 201 or result.get("state") not in {"FAILED", "UNKNOWN"}:
                failures.append(f"{provider}/{injection}: normalized failure")
            if injection != "declined" and result.get("final") is not False:
                failures.append(f"{provider}/{injection}: uncertainty finality")

        unsupported = payload(provider, PROVIDER_OPERATIONS[provider][0], "unsupported")
        if call(endpoint, unsupported, f"unsupported-{provider}-0001")[0] != 422:
            failures.append(f"{provider}: unsupported capability accepted")
        forbidden = payload(provider, PROVIDER_OPERATIONS[provider][0],
                            PROVIDER_CHANNELS[provider][0])
        forbidden["note"] = "4242424242424242"
        if call(endpoint, forbidden, f"card-data-{provider}-00001")[0] != 422:
            failures.append(f"{provider}: raw card data accepted")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    return vectors, failures


def main() -> int:
    verify_declaration()
    total = 0
    failures: list[str] = []
    for provider in PROVIDER_CHANNELS:
        vectors, provider_failures = run_provider(provider)
        total += vectors
        failures.extend(provider_failures)
        print(f"{provider}: {vectors} channel-operation vectors, failures={len(provider_failures)}")
    print(f"provider-contract-matrix: providers={len(PROVIDER_CHANNELS)} vectors={total} "
          f"failure_modes={len(CONTRACT_FAILURES)} failures={len(failures)}")
    for failure in failures:
        print(f"FAIL: {failure}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
