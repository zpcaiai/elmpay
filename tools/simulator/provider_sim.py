"""A minimal, deterministic payment-provider simulator.

Scope for B04 is the *development platform*, not protocol fidelity: the
simulator exists so that services can be brought up offline and so that the
idempotency and signature-verification behaviours the platform depends on can
be exercised before any connector exists. Full per-provider contract fidelity
is B113's job.

Behaviours that matter here and are covered by tests:

* ``/healthz`` reports the provider and that the data is synthetic;
* creating a payment requires an idempotency key; replaying the same key with
  the same payload returns the first result, a different payload returns 409
  (NN-04);
* callbacks are HMAC-signed over ``timestamp.nonce.body``; a tampered body or a
  stale timestamp fails verification (NN-08);
* the server refuses to start with production-looking credentials or with any
  payload that contains a card-number-shaped value (NN-02/NN-07).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

SUPPORTED_PROVIDERS = ("wechat", "alipay", "stripe", "paypal", "apple_pay")
# Any secret used by a simulator must be obviously synthetic.
SYNTHETIC_PREFIX = "sim-"
PRODUCTION_MARKERS = ("sk_live", "live_", "prod", "production", "-----BEGIN")
PAN_LIKE = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")
MAX_CLOCK_SKEW_SECONDS = 300


class SimulatorRefused(RuntimeError):
    """Raised when the simulator is asked to run in an unsafe configuration."""


@dataclass
class SimulatorConfig:
    provider: str
    secret: str = SYNTHETIC_PREFIX + "secret-0000"
    merchant_id: str = SYNTHETIC_PREFIX + "merchant"
    clock: Any = time.time

    def validate(self) -> None:
        if self.provider not in SUPPORTED_PROVIDERS:
            raise SimulatorRefused(f"unsupported provider '{self.provider}'")
        if not self.secret.startswith(SYNTHETIC_PREFIX):
            raise SimulatorRefused(
                "simulator secrets must be synthetic and start with 'sim-'; refusing to run "
                "with a credential that may be real (NN-07)")
        lowered = f"{self.secret}{self.merchant_id}".lower()
        for marker in PRODUCTION_MARKERS:
            if marker in lowered:
                raise SimulatorRefused(
                    f"configuration looks like production material ('{marker}'); the local "
                    f"platform must never hold production credentials (NN-07)")


@dataclass
class _Record:
    payment_id: str
    payload_hash: str
    body: dict


@dataclass
class SimulatorState:
    config: SimulatorConfig
    by_key: dict[str, _Record] = field(default_factory=dict)
    counter: int = 0
    lock: threading.Lock = field(default_factory=threading.Lock)


def _hash(payload: dict) -> str:
    canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def sign(secret: str, timestamp: str, nonce: str, body: str) -> str:
    message = f"{timestamp}.{nonce}.{body}".encode("utf-8")
    return hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()


def verify(secret: str, timestamp: str, nonce: str, body: str, signature: str,
           now: float | None = None) -> bool:
    """Constant-time verification with a bounded timestamp window."""
    try:
        skew = abs((now if now is not None else time.time()) - float(timestamp))
    except (TypeError, ValueError):
        return False
    if skew > MAX_CLOCK_SKEW_SECONDS:
        return False
    return hmac.compare_digest(sign(secret, timestamp, nonce, body), signature)


def reject_card_data(payload: Any) -> None:
    """Refuse anything that looks like a primary account number (NN-02)."""
    text = json.dumps(payload, ensure_ascii=False)
    for candidate in PAN_LIKE.findall(text):
        digits = re.sub(r"\D", "", candidate)
        if 13 <= len(digits) <= 19 and _luhn(digits):
            raise SimulatorRefused(
                "payload contains a card-number-shaped value; the platform and its simulators "
                "never accept raw PAN (NN-02)")


def _luhn(digits: str) -> bool:
    total, parity = 0, len(digits) % 2
    for index, char in enumerate(digits):
        value = int(char)
        if index % 2 == parity:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    state: SimulatorState

    def log_message(self, fmt: str, *args: Any) -> None:  # keep test output clean
        pass

    def _send(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path == "/healthz":
            self._send(200, {"status": "ok", "provider": self.state.config.provider,
                             "mode": "simulator", "data": "synthetic"})
            return
        if self.path.startswith("/payments/"):
            payment_id = self.path.rsplit("/", 1)[-1]
            for record in self.state.by_key.values():
                if record.payment_id == payment_id:
                    self._send(200, record.body)
                    return
            self._send(404, {"error": "not_found"})
            return
        self._send(404, {"error": "not_found"})

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8") if length else "{}"
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            self._send(400, {"error": "invalid_json"})
            return

        if self.path == "/payments":
            self._create_payment(payload)
        elif self.path == "/_sim/callback":
            self._build_callback(payload)
        else:
            self._send(404, {"error": "not_found"})

    def _create_payment(self, payload: dict) -> None:
        key = self.headers.get("Idempotency-Key", "")
        if not key:
            self._send(400, {"error": "idempotency_key_required"})
            return
        try:
            reject_card_data(payload)
        except SimulatorRefused as exc:
            self._send(422, {"error": "card_data_rejected", "detail": str(exc)})
            return

        digest = _hash(payload)
        state = self.state
        with state.lock:
            existing = state.by_key.get(key)
            if existing is not None:
                if existing.payload_hash != digest:
                    self._send(409, {"error": "idempotency_key_reuse_with_different_payload"})
                    return
                self._send(200, existing.body)
                return
            state.counter += 1
            payment_id = f"{state.config.provider}_sim_{state.counter:08d}"
            body = {"payment_id": payment_id, "status": "PENDING",
                    "provider": state.config.provider,
                    "amount_minor": payload.get("amount_minor"),
                    "currency": payload.get("currency"),
                    "merchant_id": state.config.merchant_id,
                    "synthetic": True}
            state.by_key[key] = _Record(payment_id, digest, body)
        self._send(201, body)

    def _build_callback(self, payload: dict) -> None:
        """Return a signed callback envelope instead of posting it.

        Returning it keeps the simulator free of outbound network access, and
        lets tests assert both the positive and the tampered case.
        """
        body = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        timestamp = str(int(self.state.config.clock()))
        nonce = hashlib.sha256(f"{timestamp}{body}".encode("utf-8")).hexdigest()[:16]
        signature = sign(self.state.config.secret, timestamp, nonce, body)
        self._send(200, {"timestamp": timestamp, "nonce": nonce,
                         "body": body, "signature": signature})


def make_server(config: SimulatorConfig, host: str = "127.0.0.1", port: int = 0) -> ThreadingHTTPServer:
    config.validate()
    handler = type("BoundHandler", (_Handler,), {"state": SimulatorState(config)})
    return ThreadingHTTPServer((host, port), handler)


def main(argv: list[str] | None = None) -> int:  # pragma: no cover - container entry point
    import argparse

    parser = argparse.ArgumentParser(description="offline payment provider simulator")
    parser.add_argument("--provider", required=True, choices=SUPPORTED_PROVIDERS)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--secret", default=SYNTHETIC_PREFIX + "secret-0000")
    args = parser.parse_args(argv)
    server = make_server(SimulatorConfig(provider=args.provider, secret=args.secret),
                         host=args.host, port=args.port)
    server.serve_forever()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
