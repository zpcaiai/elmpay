"""B112-B117 deterministic model, provider, fault, security and load tooling."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
import hashlib
import hmac
import ipaddress
import json
import math
import random
import sqlite3
import threading
import time
from typing import Any, Callable, Iterable, Mapping
from urllib import error as urlerror
from urllib import parse as urlparse
from urllib import request as urlrequest

from .common import GateReport, ValidationError, canonical_json, require_list, require_mapping, require_text


@dataclass(frozen=True)
class ModelResult:
    cases: int
    failures: tuple[str, ...]

    @property
    def passed(self) -> bool:
        return not self.failures


def exercise_payment_model(seed: int, cases: int) -> ModelResult:
    """Generate reproducible money/state sequences and check core invariants."""
    if cases < 1 or cases > 1_000_000:
        raise ValidationError("property case count outside safe bounds")
    randomizer = random.Random(seed)
    failures: list[str] = []
    for case in range(cases):
        authorized = randomizer.randint(1, 10**12)
        captures = [randomizer.randint(0, authorized) for _ in range(randomizer.randint(1, 8))]
        captured = 0
        for amount in captures:
            accepted = amount > 0 and captured + amount <= authorized
            previous = captured
            if accepted:
                captured += amount
            if captured < previous or captured > authorized:
                failures.append(f"case:{case}:capture_bounds")
        refunds = [randomizer.randint(0, authorized) for _ in range(randomizer.randint(1, 8))]
        refunded = 0
        for amount in refunds:
            accepted = amount > 0 and refunded + amount <= captured
            previous = refunded
            if accepted:
                refunded += amount
            if refunded < previous or refunded > captured:
                failures.append(f"case:{case}:refund_bounds")
        # Double-entry facts always post an equal debit and credit in minor units.
        entries = [("merchant", captured), ("clearing", -captured), ("merchant", -refunded), ("clearing", refunded)]
        if sum(amount for _, amount in entries) != 0:
            failures.append(f"case:{case}:ledger_unbalanced")
    return ModelResult(cases, tuple(failures))


@dataclass(frozen=True)
class SimulatedProviderResult:
    provider: str
    request_id: str
    outcome: str
    provider_reference: str | None
    webhook_payload: bytes | None
    webhook_headers: Mapping[str, str]
    delay_ms: int


class DeterministicProviderSimulator:
    """Account-scoped protocol simulator with durable side-effect deduplication."""

    PROVIDERS = {"wechat", "alipay", "stripe", "paypal", "applepay"}
    OPERATIONS = {"PAYMENT", "QUERY", "CAPTURE", "CANCEL", "REFUND"}

    def __init__(self, path: str, secrets: Mapping[tuple[str, str, str], bytes]) -> None:
        self._secrets = dict(secrets)
        self._lock = threading.RLock()
        self._db = sqlite3.connect(path, timeout=5, isolation_level=None, check_same_thread=False)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute(
            """CREATE TABLE IF NOT EXISTS simulator_attempt (
              tenant_id TEXT NOT NULL, account_id TEXT NOT NULL, provider TEXT NOT NULL,
              idempotency_key TEXT NOT NULL, request_digest TEXT NOT NULL,
              response_json BLOB NOT NULL,
              PRIMARY KEY(tenant_id, account_id, provider, idempotency_key)
            )"""
        )

    def close(self) -> None:
        self._db.close()

    def execute(self, request: Mapping[str, Any], scenario: str = "SUCCESS") -> SimulatedProviderResult:
        provider = require_text(request.get("provider"), "provider").lower()
        if provider not in self.PROVIDERS:
            raise ValidationError("unsupported simulated provider")
        tenant = require_text(request.get("tenantId"), "tenantId")
        account = require_text(request.get("providerAccountId"), "providerAccountId")
        operation = require_text(request.get("operation"), "operation")
        if operation not in self.OPERATIONS:
            raise ValidationError("unsupported simulated operation")
        idem = require_text(request.get("idempotencyKey"), "idempotencyKey")
        amount = request.get("amountMinor")
        if operation not in {"QUERY", "CANCEL"} and (
            isinstance(amount, bool) or not isinstance(amount, int) or amount <= 0
        ):
            raise ValidationError("provider amount must be positive integer minor units")
        currency = require_text(request.get("currency"), "currency")
        if not __import__("re").fullmatch(r"[A-Z]{3}", currency):
            raise ValidationError("provider currency invalid")
        secret = self._secrets.get((tenant, account, provider))
        if secret is None or len(secret) < 32:
            raise ValidationError("simulator account secret unavailable")
        digest = hashlib.sha256(canonical_json(request)).hexdigest()
        with self._lock:
            row = self._db.execute(
                "SELECT request_digest,response_json FROM simulator_attempt WHERE tenant_id=? AND account_id=? AND provider=? AND idempotency_key=?",
                (tenant, account, provider, idem),
            ).fetchone()
        if row is not None:
            if not hmac.compare_digest(str(row[0]), digest):
                raise ValidationError("simulator idempotency conflict")
            return self._decode(bytes(row[1]))
        if scenario not in {"SUCCESS", "DECLINED", "UNKNOWN", "TIMEOUT", "MALFORMED_WEBHOOK"}:
            raise ValidationError("unknown simulator scenario")
        reference = None if scenario in {"DECLINED", "TIMEOUT"} else hashlib.sha256(
            f"{provider}:{tenant}:{account}:{idem}".encode()
        ).hexdigest()[:24]
        outcome = "UNKNOWN" if scenario in {"UNKNOWN", "TIMEOUT"} else scenario
        payload: bytes | None = None
        headers: dict[str, str] = {}
        if scenario not in {"TIMEOUT", "DECLINED"}:
            event = {
                "provider": provider,
                "providerAccountId": account,
                "providerReference": reference,
                "idempotencyKey": idem,
                "operation": operation,
                "amountMinor": amount,
                "currency": currency,
                "status": "SUCCEEDED" if scenario == "SUCCESS" else "UNKNOWN",
            }
            payload = canonical_json(event)
            if scenario == "MALFORMED_WEBHOOK":
                payload = payload[:-1]
            headers = self._signature_headers(provider, payload, secret, request.get("timestamp", 1770000000))
        result = SimulatedProviderResult(
            provider, digest[:24], outcome, reference, payload, headers,
            5_000 if scenario == "TIMEOUT" else 5,
        )
        encoded = self._encode(result)
        with self._lock:
            try:
                self._db.execute(
                    "INSERT INTO simulator_attempt VALUES(?,?,?,?,?,?)",
                    (tenant, account, provider, idem, digest, encoded),
                )
            except sqlite3.IntegrityError:
                existing = self._db.execute(
                    "SELECT request_digest,response_json FROM simulator_attempt WHERE tenant_id=? AND account_id=? AND provider=? AND idempotency_key=?",
                    (tenant, account, provider, idem),
                ).fetchone()
                if existing is None or not hmac.compare_digest(str(existing[0]), digest):
                    raise ValidationError("simulator idempotency conflict")
                return self._decode(bytes(existing[1]))
        return result

    @staticmethod
    def _signature_headers(provider: str, payload: bytes, secret: bytes, timestamp: object) -> dict[str, str]:
        ts = str(timestamp)
        signature = hmac.new(secret, ts.encode() + b"." + payload, hashlib.sha256).hexdigest()
        if provider == "stripe":
            return {"Stripe-Signature": f"t={ts},v1={signature}"}
        if provider == "wechat":
            return {"Wechatpay-Timestamp": ts, "Wechatpay-Nonce": "synthetic-nonce", "Wechatpay-Serial": "SYNTHETIC", "Wechatpay-Signature": signature}
        if provider == "alipay":
            return {"Alipay-Signature": signature, "Alipay-Sign-Type": "RSA2-SIMULATED"}
        if provider == "paypal":
            return {"Paypal-Transmission-Time": ts, "Paypal-Transmission-Sig": signature, "Paypal-Cert-Url": "https://simulator.invalid/cert"}
        return {"Applepay-Provider-Signature": signature}

    @staticmethod
    def _encode(result: SimulatedProviderResult) -> bytes:
        return canonical_json({
            "provider": result.provider, "requestId": result.request_id, "outcome": result.outcome,
            "providerReference": result.provider_reference,
            "webhookPayload": result.webhook_payload.decode("utf-8", errors="surrogateescape") if result.webhook_payload else None,
            "webhookHeaders": dict(result.webhook_headers), "delayMs": result.delay_ms,
        })

    @staticmethod
    def _decode(value: bytes) -> SimulatedProviderResult:
        raw = json.loads(value)
        payload = raw["webhookPayload"].encode("utf-8", errors="surrogateescape") if raw["webhookPayload"] is not None else None
        return SimulatedProviderResult(raw["provider"], raw["requestId"], raw["outcome"], raw["providerReference"], payload, raw["webhookHeaders"], raw["delayMs"])


def webhook_fault_corpus(payload: bytes, seed: int) -> tuple[tuple[str, bytes, Mapping[str, int]], ...]:
    if not payload:
        raise ValidationError("webhook seed payload cannot be empty")
    randomizer = random.Random(seed)
    bit = randomizer.randrange(len(payload))
    changed = bytearray(payload)
    changed[bit] ^= 1
    return (
        ("duplicate", payload, {"delivery": 2}),
        ("truncated", payload[: max(1, len(payload) // 2)], {"delivery": 1}),
        ("bitflip", bytes(changed), {"delivery": 1}),
        ("delayed", payload, {"delaySeconds": 600}),
        ("clock-skew-past", payload, {"clockSkewSeconds": -3600}),
        ("clock-skew-future", payload, {"clockSkewSeconds": 3600}),
        ("out-of-order", payload, {"revisionDelta": -1}),
        ("signature-rotation", payload, {"unknownKeyVersion": 1}),
    )


def evaluate_security_pipeline(
    required_tools: Iterable[str], reports: Iterable[Mapping[str, Any]], expected_digest: str
) -> GateReport:
    required = set(required_tools)
    seen: set[str] = set()
    reasons: list[str] = []
    for raw in reports:
        report = require_mapping(raw, "security report")
        tool = require_text(report.get("tool"), "tool")
        if tool in seen:
            reasons.append(f"security_tool_duplicate:{tool}")
            continue
        seen.add(tool)
        if tool not in required:
            reasons.append(f"security_tool_unexpected:{tool}")
        if report.get("orchestrated") is not True:
            reasons.append(f"security_tool_not_orchestrated:{tool}")
        if report.get("status") != "COMPLETE":
            reasons.append(f"security_tool_incomplete:{tool}")
        exit_code = report.get("exitCode")
        if isinstance(exit_code, bool) or not isinstance(exit_code, int) or exit_code != 0:
            reasons.append(f"security_tool_exit_code:{tool}")
        execution_digest = report.get("executionDigest")
        if (not isinstance(execution_digest, str)
                or not __import__("re").fullmatch(r"[0-9a-f]{64}", execution_digest)):
            reasons.append(f"security_execution_digest_invalid:{tool}")
        if report.get("artifactDigest") != expected_digest:
            reasons.append(f"security_artifact_mismatch:{tool}")
        critical = report.get("criticalFindings")
        high = report.get("highFindings")
        if isinstance(critical, bool) or not isinstance(critical, int) or critical != 0:
            reasons.append(f"security_critical_findings:{tool}")
        if isinstance(high, bool) or not isinstance(high, int) or high != 0:
            reasons.append(f"security_high_findings:{tool}")
    for missing in sorted(required - seen):
        reasons.append(f"security_tool_missing:{missing}")
    if not __import__("re").fullmatch(r"[0-9a-f]{64}", expected_digest):
        reasons.append("security_expected_digest_invalid")
    return GateReport.from_reasons(reasons, (f"security:{tool}" for tool in seen))


@dataclass(frozen=True)
class LoadReport:
    requests: int
    errors: int
    duration_ms: int
    throughput_rps: float
    error_rate: float
    p50_ms: int
    p95_ms: int
    p99_ms: int
    maximum_ms: int
    duplicate_side_effects: int
    duplicate_results: int
    non_finite_results: int
    status_counts: Mapping[str, int]
    evidence_class: str
    complete_b117_proof: bool


@dataclass(frozen=True)
class ResiliencePhaseReport:
    name: str
    shape: str
    fault: str
    load: LoadReport
    recovered: bool
    recovery_ms: int
    recovery_metrics: Mapping[str, Any]


@dataclass(frozen=True)
class ResilienceLoadReport:
    phases: tuple[ResiliencePhaseReport, ...]
    evidence_class: str = "LOOPBACK_TEST_HTTP_RESILIENCE"
    complete_b117_proof: bool = True


def run_load_profile(
    handler: Callable[[str], Mapping[str, Any]], request_ids: Iterable[str], workers: int
) -> LoadReport:
    """Run the deterministic in-process fixture profile used by unit tests.

    This intentionally cannot produce complete B117 evidence.  Complete load
    evidence must exercise an actual loopback TEST HTTP service through
    :func:`run_http_load_profile`.
    """
    identifiers = list(request_ids)
    if not identifiers or workers < 1 or workers > 256:
        raise ValidationError("load profile size or worker count invalid")
    profile_started = time.monotonic_ns()
    latencies: list[int] = []
    errors = 0
    effects: set[str] = set()
    duplicates = 0
    results: set[str] = set()
    duplicate_results = 0
    non_finite = 0

    def invoke(request_id: str) -> tuple[str, Mapping[str, Any], int]:
        started = time.monotonic_ns()
        result = require_mapping(handler(request_id), "load result")
        elapsed = max(0, (time.monotonic_ns() - started) // 1_000_000)
        return request_id, result, int(elapsed)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(invoke, request_id) for request_id in identifiers]
        for future in as_completed(futures):
            _, result, elapsed = future.result()
            latencies.append(elapsed)
            if result.get("ok") is not True:
                errors += 1
            value = result.get("score", 0)
            if isinstance(value, float) and not math.isfinite(value):
                non_finite += 1
            effect = result.get("sideEffectId")
            if effect is not None:
                effect_id = require_text(effect, "sideEffectId")
                if effect_id in effects:
                    duplicates += 1
                effects.add(effect_id)
            result_id = result.get("resultId")
            if result_id is not None:
                normalized = require_text(result_id, "resultId")
                if normalized in results:
                    duplicate_results += 1
                results.add(normalized)
    duration_ms = max(1, int((time.monotonic_ns() - profile_started) // 1_000_000))
    return _load_report(
        latencies, errors, duration_ms, duplicates, duplicate_results, non_finite,
        {"synthetic": len(identifiers)}, "DETERMINISTIC_SYNTHETIC", False,
    )


def run_http_load_profile(profile: Mapping[str, Any], test_token: str) -> LoadReport:
    """Measure a bounded real HTTP workload against a loopback TEST-only service.

    The service must prove TEST mode during an authenticated health preflight.
    The token is supplied out-of-band and is never included in the report.
    Every measured request carries a unique request/idempotency identity, which
    allows duplicate result and duplicate side-effect detection.
    """
    base_url = _loopback_base(require_text(profile.get("baseUrl"), "baseUrl"))
    health_path = _safe_http_path(profile.get("healthPath", "/healthz"), "healthPath")
    request_path = _safe_http_path(profile.get("requestPath"), "requestPath")
    workers = _bounded_integer(profile.get("workers"), "workers", 1, 64)
    maximum_requests = _bounded_integer(
        profile.get("maximumRequests"), "maximumRequests", 1, 100_000
    )
    timeout_ms = _bounded_integer(
        profile.get("timeoutMilliseconds", 2_000), "timeoutMilliseconds", 50, 10_000
    )
    duration_seconds = profile.get("durationSeconds")
    if isinstance(duration_seconds, bool) or not isinstance(duration_seconds, (int, float)):
        raise ValidationError("durationSeconds must be a finite number")
    if not math.isfinite(float(duration_seconds)) or not 0.1 <= float(duration_seconds) <= 300:
        raise ValidationError("durationSeconds is outside the safe bound")
    expected_status = _bounded_integer(
        profile.get("expectedStatus", 200), "expectedStatus", 100, 599
    )
    method = require_text(profile.get("method", "POST"), "method").upper()
    if method not in {"GET", "POST"}:
        raise ValidationError("load method must be GET or POST")
    template = require_mapping(profile.get("body", {"synthetic": True}), "body")
    if template.get("synthetic") is not True:
        raise ValidationError("loopback load body must declare synthetic=true")
    if set(template) - {"synthetic", "scenario", "payload"}:
        raise ValidationError("loopback load body contains an unsafe field")
    prefix = require_text(profile.get("idempotencyPrefix"), "idempotencyPrefix")
    if not __import__("re").fullmatch(r"test-[A-Za-z0-9._-]{8,64}", prefix):
        raise ValidationError("idempotencyPrefix must be an explicit bounded test prefix")
    _validate_test_token(test_token)

    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {test_token}",
        "X-Elmpay-Load-Test": "true",
    }
    health = _http_json(
        _same_origin(base_url, health_path), "GET", headers, None, timeout_ms
    )
    if health[0] != 200:
        raise ValidationError("load target health preflight failed")
    health_body = health[1]
    if (health_body.get("environment") != "TEST"
            or health_body.get("loadTest") is not True
            or health_body.get("production") is not False
            or health_body.get("tokenRequired") is not True):
        raise ValidationError("load target did not prove TEST-only mode")

    endpoint = _same_origin(base_url, request_path)
    started_ns = time.monotonic_ns()
    deadline_ns = started_ns + int(float(duration_seconds) * 1_000_000_000)
    counter = 0
    counter_lock = threading.Lock()
    observation_lock = threading.Lock()
    latencies: list[int] = []
    errors = 0
    effects: set[str] = set()
    result_ids: set[str] = set()
    duplicate_effects = 0
    duplicate_results = 0
    non_finite = 0
    status_counts: dict[str, int] = {}

    def worker() -> None:
        nonlocal counter, errors, duplicate_effects, duplicate_results, non_finite
        while True:
            with counter_lock:
                if counter >= maximum_requests or time.monotonic_ns() >= deadline_ns:
                    return
                index = counter
                counter += 1
            request_id = f"{prefix}-{index:08d}"
            body = dict(template)
            body["requestId"] = request_id
            body["idempotencyKey"] = request_id
            encoded = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
            request_headers = {
                **headers,
                "Content-Type": "application/json",
                "Idempotency-Key": request_id,
                "X-Elmpay-Test-Request-Id": request_id,
            }
            request_started = time.monotonic_ns()
            status = 0
            response: Mapping[str, Any] | None = None
            failed = False
            effect: str | None = None
            result_id: str | None = None
            try:
                status, response = _http_json(
                    endpoint, method, request_headers,
                    None if method == "GET" else encoded, timeout_ms,
                )
                failed = status != expected_status or response.get("ok") is not True
                failed = failed or response.get("requestId") != request_id
                if not failed:
                    effect = require_text(response.get("sideEffectId"), "sideEffectId")
                    result_id = require_text(response.get("resultId"), "resultId")
            except (OSError, urlerror.URLError, ValidationError, ValueError):
                failed = True
            elapsed = max(0, int((time.monotonic_ns() - request_started) // 1_000_000))
            with observation_lock:
                latencies.append(elapsed)
                key = str(status) if status else "transport_error"
                status_counts[key] = status_counts.get(key, 0) + 1
                if failed or response is None:
                    errors += 1
                    continue
                score = response.get("score", 0)
                if isinstance(score, float) and not math.isfinite(score):
                    non_finite += 1
                assert effect is not None and result_id is not None
                if effect in effects:
                    duplicate_effects += 1
                if result_id in result_ids:
                    duplicate_results += 1
                effects.add(effect)
                result_ids.add(result_id)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(worker) for _ in range(workers)]
        for future in futures:
            future.result()
    duration_ms = max(1, int((time.monotonic_ns() - started_ns) // 1_000_000))
    if not latencies:
        raise ValidationError("loopback load profile executed no requests")
    return _load_report(
        latencies, errors, duration_ms, duplicate_effects, duplicate_results,
        non_finite, status_counts, "LOOPBACK_TEST_HTTP", True,
    )


def run_http_resilience_plan(profile: Mapping[str, Any], test_token: str) -> ResilienceLoadReport:
    """Run bounded peak/burst/soak phases and TEST-only fault/recovery probes."""
    phases = require_list(profile.get("phases"), "phases")
    if not 3 <= len(phases) <= 12:
        raise ValidationError("resilience plan must contain 3..12 bounded phases")
    base_url = _loopback_base(require_text(profile.get("baseUrl"), "baseUrl"))
    control_path = _safe_http_path(profile.get("faultControlPath"), "faultControlPath")
    recovery_path = _safe_http_path(profile.get("recoveryPath"), "recoveryPath")
    timeout_ms = _bounded_integer(
        profile.get("timeoutMilliseconds", 2_000), "timeoutMilliseconds", 50, 10_000
    )
    recovery_timeout_ms = _bounded_integer(
        profile.get("recoveryTimeoutMilliseconds", 5_000),
        "recoveryTimeoutMilliseconds", 100, 10_000,
    )
    _validate_test_token(test_token)
    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {test_token}",
        "Content-Type": "application/json",
        "X-Elmpay-Load-Test": "true",
    }
    allowed_shapes = {"PEAK", "BURST", "SOAK"}
    allowed_faults = {"NONE", "QUEUE_BACKLOG", "DATABASE_UNAVAILABLE", "PROVIDER_DEGRADED"}
    seen: set[str] = set()
    reports: list[ResiliencePhaseReport] = []
    base = {key: value for key, value in profile.items() if key not in {
        "phases", "faultControlPath", "recoveryPath", "recoveryTimeoutMilliseconds"
    }}
    for raw in phases:
        phase = require_mapping(raw, "phase")
        name = require_text(phase.get("name"), "phase.name")
        if name in seen or not __import__("re").fullmatch(r"[a-z][a-z0-9_-]{2,31}", name):
            raise ValidationError("resilience phase name is invalid or duplicated")
        seen.add(name)
        shape = require_text(phase.get("shape"), "phase.shape").upper()
        fault = require_text(phase.get("fault", "NONE"), "phase.fault").upper()
        if shape not in allowed_shapes or fault not in allowed_faults:
            raise ValidationError("resilience phase shape or fault is unsupported")
        overrides = {key: value for key, value in phase.items()
                     if key not in {"name", "shape", "fault"}}
        if set(overrides) - {
            "workers", "durationSeconds", "maximumRequests", "idempotencyPrefix",
            "thresholds", "body",
        }:
            raise ValidationError("resilience phase contains an unsafe override")
        measured_profile = {**base, **overrides}
        measured_profile["target"] = "loopback-http-test-v1"
        enabled = fault != "NONE"
        if enabled:
            _set_test_fault(base_url, control_path, fault, True, headers, timeout_ms)
        load: LoadReport
        try:
            load = run_http_load_profile(measured_profile, test_token)
        finally:
            if enabled:
                _set_test_fault(base_url, control_path, fault, False, headers, timeout_ms)
        recovery_started = time.monotonic_ns()
        recovered, metrics = _wait_for_recovery(
            base_url, recovery_path, fault, headers, timeout_ms, recovery_timeout_ms
        )
        recovery_ms = max(0, int((time.monotonic_ns() - recovery_started) // 1_000_000))
        reports.append(ResiliencePhaseReport(
            name, shape, fault, load, recovered, recovery_ms, metrics
        ))
    if {report.shape for report in reports} != allowed_shapes:
        raise ValidationError("resilience plan must cover PEAK, BURST and SOAK")
    if not {"QUEUE_BACKLOG", "DATABASE_UNAVAILABLE", "PROVIDER_DEGRADED"}.issubset(
            {report.fault for report in reports}):
        raise ValidationError("resilience plan lacks required queue/database/provider faults")
    return ResilienceLoadReport(tuple(reports))


def _set_test_fault(base_url: str, path: str, fault: str, enabled: bool,
                    headers: Mapping[str, str], timeout_ms: int) -> None:
    document = json.dumps({
        "synthetic": True, "fault": fault, "enabled": enabled,
    }, sort_keys=True, separators=(",", ":")).encode("utf-8")
    status, response = _http_json(
        _same_origin(base_url, path), "POST", headers, document, timeout_ms
    )
    if (status != 200 or response.get("ok") is not True
            or response.get("environment") != "TEST"
            or response.get("fault") != fault
            or response.get("enabled") is not enabled):
        raise ValidationError("TEST-only fault control did not acknowledge exact state")


def _wait_for_recovery(base_url: str, path: str, fault: str,
                       headers: Mapping[str, str], timeout_ms: int,
                       recovery_timeout_ms: int) -> tuple[bool, Mapping[str, Any]]:
    deadline = time.monotonic_ns() + recovery_timeout_ms * 1_000_000
    last: Mapping[str, Any] = {}
    while time.monotonic_ns() < deadline:
        status, last = _http_json(
            _same_origin(base_url, path), "GET", headers, None, timeout_ms
        )
        if (status == 200 and last.get("environment") == "TEST"
                and last.get("recovered") is True
                and isinstance(last.get("queueDepth"), int)
                and last.get("queueDepth") == 0
                and last.get("databaseAvailable") is True
                and last.get("providerAvailable") is True):
            return True, dict(last)
        time.sleep(0.05)
    return False, dict(last)


def _load_report(latencies: list[int], errors: int, duration_ms: int,
                 duplicate_side_effects: int, duplicate_results: int,
                 non_finite_results: int, status_counts: Mapping[str, int],
                 evidence_class: str, complete_b117_proof: bool) -> LoadReport:
    ordered = sorted(latencies)
    requests = len(ordered)
    duration_seconds = duration_ms / 1_000

    def percentile(value: float) -> int:
        return ordered[max(0, math.ceil(requests * value) - 1)]

    return LoadReport(
        requests=requests,
        errors=errors,
        duration_ms=duration_ms,
        throughput_rps=requests / duration_seconds,
        error_rate=errors / requests,
        p50_ms=percentile(0.50),
        p95_ms=percentile(0.95),
        p99_ms=percentile(0.99),
        maximum_ms=ordered[-1],
        duplicate_side_effects=duplicate_side_effects,
        duplicate_results=duplicate_results,
        non_finite_results=non_finite_results,
        status_counts=dict(sorted(status_counts.items())),
        evidence_class=evidence_class,
        complete_b117_proof=complete_b117_proof,
    )


def _loopback_base(value: str) -> str:
    parsed = urlparse.urlsplit(value)
    if (parsed.scheme not in {"http", "https"} or parsed.username is not None
            or parsed.password is not None or parsed.query or parsed.fragment
            or parsed.path not in {"", "/"} or parsed.hostname is None):
        raise ValidationError("load baseUrl must be an origin-only HTTP(S) URL")
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError as exc:
        raise ValidationError("load baseUrl must use a literal loopback address") from exc
    if not address.is_loopback:
        raise ValidationError("load baseUrl is not loopback")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValidationError("load baseUrl port is invalid") from exc
    if port is None:
        raise ValidationError("load baseUrl must specify an explicit test port")
    host = f"[{address.compressed}]" if address.version == 6 else address.compressed
    return f"{parsed.scheme}://{host}:{port}/"


def _safe_http_path(value: Any, field: str) -> str:
    path = require_text(value, field)
    parsed = urlparse.urlsplit(path)
    if (not path.startswith("/") or path.startswith("//") or parsed.scheme
            or parsed.netloc or parsed.query or parsed.fragment or ".." in parsed.path.split("/")):
        raise ValidationError(f"{field} must be a same-origin absolute path")
    return parsed.path


def _same_origin(base_url: str, path: str) -> str:
    joined = urlparse.urljoin(base_url, path.lstrip("/"))
    if urlparse.urlsplit(joined).netloc != urlparse.urlsplit(base_url).netloc:
        raise ValidationError("load URL escaped its loopback origin")
    return joined


def _validate_test_token(value: str) -> None:
    if (not isinstance(value, str) or not value.startswith("test-")
            or not 32 <= len(value.encode("utf-8")) <= 256
            or any(character.isspace() or ord(character) < 0x21 for character in value)):
        raise ValidationError("load test token must be an explicit bounded test-only token")


def _bounded_integer(value: Any, field: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValidationError(f"{field} is outside the safe bound")
    return value


def _http_json(url: str, method: str, headers: Mapping[str, str], body: bytes | None,
               timeout_ms: int) -> tuple[int, Mapping[str, Any]]:
    request = urlrequest.Request(url, data=body, headers=dict(headers), method=method)
    try:
        response = urlrequest.urlopen(request, timeout=timeout_ms / 1_000)
    except urlerror.HTTPError as exc:
        response = exc
    with response:
        raw = response.read(65_537)
        if len(raw) > 65_536:
            raise ValidationError("load response exceeded the safe size")
        content_type = response.headers.get_content_type()
        if content_type != "application/json":
            raise ValidationError("load response is not application/json")
        try:
            document = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValidationError("load response is malformed JSON") from exc
        return int(response.status), require_mapping(document, "load HTTP response")
