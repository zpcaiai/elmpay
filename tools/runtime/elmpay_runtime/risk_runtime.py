"""Authenticated synchronous product endpoint for the durable risk control plane."""
from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import hashlib
import hmac
import json
import threading
from typing import Any, Callable, Mapping, Protocol
import urllib.error
import urllib.request

from .common import ValidationError, canonical_json, require_mapping, require_text
from .risk_control import ModelClient, ModelResult, RiskEvaluation, SQLiteRiskControl


class RiskSignalProvider(Protocol):
    def collect(self, request: Mapping[str, Any], now: datetime) -> Mapping[str, Any]: ...


class LocalSandboxRiskSignalProvider:
    """Deterministic low-risk signals, constructible only by the explicit local CLI mode."""

    def collect(self, request: Mapping[str, Any], now: datetime) -> Mapping[str, Any]:
        tenant = require_text(request.get("tenantId"), "tenantId")
        current = now.astimezone(timezone.utc)
        return {
            "tenantId": tenant,
            "version": "local-sandbox-" + current.strftime("%Y%m%d%H%M"),
            "collectedAt": current.isoformat(),
            "expiresAt": (current + timedelta(seconds=60)).isoformat(),
            "values": {
                "velocity5m": "0",
                "deviceReputation": "1",
                "networkReputation": "1",
                "geoAnomaly": "0",
                "accountAgeDays": "365",
                "behaviorSequenceRisk": "0",
            },
        }


class HttpRiskSignalProvider:
    """Finite HTTPS adapter to the trusted server-side signal aggregation service."""

    def __init__(self, endpoint: str, bearer_token: str, timeout_milliseconds: int = 100) -> None:
        if not endpoint.startswith("https://"):
            raise ValidationError("risk signal endpoint must use HTTPS")
        self._endpoint = endpoint
        self._token = require_text(bearer_token, "risk signal bearer token")
        if not 1 <= timeout_milliseconds <= 2_000:
            raise ValidationError("risk signal timeout must be within 1..2000ms")
        self._timeout = timeout_milliseconds / 1_000

    def collect(self, request: Mapping[str, Any], now: datetime) -> Mapping[str, Any]:
        message = urllib.request.Request(
            self._endpoint,
            data=canonical_json(request),
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Authorization": "Bearer " + self._token,
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(message, timeout=self._timeout) as response:
                if response.status != 200:
                    raise ValidationError("risk signal service returned non-success")
                raw = response.read(65_537)
                if len(raw) > 65_536:
                    raise ValidationError("risk signal response too large")
                document = json.loads(raw, parse_constant=lambda value: (_ for _ in ()).throw(
                    ValidationError(f"risk signal service returned non-finite {value}")
                ))
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValidationError("risk signal service unavailable or malformed") from exc
        result = require_mapping(document, "risk signal response")
        if set(result) != {"tenantId", "version", "collectedAt", "expiresAt", "values"}:
            raise ValidationError("risk signal response schema invalid")
        return result


class UnavailableModelClient:
    """Explicit fail-closed model fallback; it can never produce an approval by itself."""

    def score(self, request: Mapping[str, Any], timeout_milliseconds: int) -> ModelResult:
        del request, timeout_milliseconds
        return ModelResult(False, "unavailable", "0" * 64, Decimal("0"), "MODEL_UNAVAILABLE")


class RiskRuntimeService:
    """Composes trusted signals with the atomic decision/outbox transaction."""

    def __init__(self, control: SQLiteRiskControl, signals: RiskSignalProvider,
                 model: ModelClient, clock: Callable[[], datetime]) -> None:
        self._control = control
        self._signals = signals
        self._model = model
        self._clock = clock

    def evaluate(self, request: Mapping[str, Any]) -> RiskEvaluation:
        current = self._clock().astimezone(timezone.utc)
        signals = self._signals.collect(request, current)
        return self._control.decide(request, signals, self._model, now=current)


class HmacRequestAuthenticator:
    """Short-lived HMAC request authentication with in-process nonce replay rejection."""

    def __init__(self, secret: bytes, clock: Callable[[], datetime], maximum_skew_seconds: int = 60) -> None:
        if len(secret) < 32:
            raise ValidationError("risk HMAC secret must contain at least 32 bytes")
        self._secret = bytes(secret)
        self._clock = clock
        self._maximum_skew = maximum_skew_seconds
        self._nonces: dict[str, int] = {}
        self._lock = threading.Lock()

    def verify(self, body: bytes, timestamp: str, nonce: str, signature: str) -> None:
        if not nonce or len(nonce) > 128 or not signature or len(signature) != 64:
            raise ValidationError("risk request authentication invalid")
        try:
            seconds = int(timestamp)
        except (TypeError, ValueError) as exc:
            raise ValidationError("risk request authentication invalid") from exc
        current = int(self._clock().timestamp())
        if abs(current - seconds) > self._maximum_skew:
            raise ValidationError("risk request authentication expired")
        content_digest = hashlib.sha256(body).hexdigest()
        expected = hmac.new(self._secret,
                            f"{timestamp}\n{nonce}\n{content_digest}".encode(),
                            hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, signature):
            raise ValidationError("risk request authentication invalid")
        with self._lock:
            for used_nonce, used_at in tuple(self._nonces.items()):
                if current - used_at > self._maximum_skew:
                    del self._nonces[used_nonce]
            if nonce in self._nonces:
                raise ValidationError("risk request nonce replayed")
            if len(self._nonces) >= 100_000:
                raise ValidationError("risk request nonce capacity exceeded")
            self._nonces[nonce] = current


def encode_evaluation(value: RiskEvaluation) -> dict[str, Any]:
    """Public wire form shared by the HTTP runtime and adapter contract tests."""
    document = asdict(value)
    return {
        "decisionId": document["decision_id"],
        "tenantId": document["tenant_id"],
        "requestId": document["request_id"],
        "operation": document["operation"],
        "subjectDigest": document["subject_digest"],
        "action": document["action"],
        "reasonCodes": list(document["reason_codes"]),
        "ruleSetVersion": document["rule_set_version"],
        "ruleSetDigest": document["rule_set_digest"],
        "signalVersion": document["signal_version"],
        "modelVersion": document["model_version"],
        "degraded": document["degraded"],
        "decidedAt": value.decided_at.astimezone(timezone.utc).isoformat(),
    }
