"""Durable B96 telemetry and B99 security-monitoring runtime.

The module deliberately separates local runtime capability from external
deployment evidence:

* service calls emit redacted, tenant/trace/correlation-bound OTLP HTTP/JSON
  envelopes into a durable outbox before an exporter is attempted;
* security events are accepted only from an Ed25519 DSSE trust root, with exact
  source/schema/binding/freshness and durable nonce checks;
* SIEM alerts remain pending until a downstream system returns a signed,
  independently verifiable receipt.  A caller-supplied boolean can never mark an
  alert exported.

HTTP is TLS-only in production.  Literal loopback HTTP is available solely for
bounded integration tests and must be explicitly enabled by configuration.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import http.client
import ipaddress
import json
import math
from pathlib import Path
import re
import sqlite3
import ssl
import time
from typing import Any, Callable, Mapping, Protocol, TypeVar
from urllib.parse import urlsplit

from .attestation import nonce_store_from_trust, verify_dsse_record
from .common import (
    ValidationError,
    canonical_json,
    parse_instant,
    require_list,
    require_mapping,
    require_text,
    sha256_json,
)
from .downstream_receipt import verify_downstream_receipt
from .operations import SecurityAlert, evaluate_security_events, telemetry_record


_TRACE = re.compile(r"^[0-9a-f]{32}$")
_SPAN = re.compile(r"^[0-9a-f]{16}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,159}$")
_SIGNALS = frozenset({"logs", "metrics", "traces"})
_OTLP_PATH = {"logs": "/v1/logs", "metrics": "/v1/metrics", "traces": "/v1/traces"}
_TERMINAL_TELEMETRY_STATES = frozenset({"DELIVERED", "FAILED", "UNKNOWN"})


def _utc(value: datetime | None = None) -> datetime:
    return (value or datetime.now(timezone.utc)).astimezone(timezone.utc)


def _instant(value: datetime | None = None) -> str:
    return _utc(value).isoformat()


def _unix_nano(value: datetime) -> str:
    current = value.astimezone(timezone.utc)
    return str(int(current.timestamp() * 1_000_000_000))


def _identifier(value: object, field: str) -> str:
    text = require_text(value, field)
    if not _IDENTIFIER.fullmatch(text):
        raise ValidationError(f"{field} has an invalid identifier format")
    return text


def _bounded_int(value: object, field: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValidationError(f"{field} is outside the safe bound")
    return value


def _otlp_value(value: Any) -> dict[str, Any]:
    if value is None:
        return {"stringValue": "null"}
    if isinstance(value, bool):
        return {"boolValue": value}
    if isinstance(value, int):
        return {"intValue": str(value)}
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValidationError("OTLP attributes cannot contain non-finite numbers")
        return {"doubleValue": value}
    if isinstance(value, str):
        return {"stringValue": value}
    if isinstance(value, Mapping):
        return {
            "kvlistValue": {
                "values": [
                    {"key": str(key), "value": _otlp_value(item)}
                    for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
                ]
            }
        }
    if isinstance(value, (list, tuple)):
        return {"arrayValue": {"values": [_otlp_value(item) for item in value]}}
    raise ValidationError(f"unsupported OTLP attribute type: {type(value).__name__}")


def _otlp_attributes(values: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [
        {"key": str(key), "value": _otlp_value(value)}
        for key, value in sorted(values.items(), key=lambda pair: str(pair[0]))
    ]


def _trace_bytes(value: str, field: str, pattern: re.Pattern[str]) -> str:
    if not pattern.fullmatch(value):
        raise ValidationError(f"{field} is invalid")
    return base64.b64encode(bytes.fromhex(value)).decode("ascii")


class _ClosingConnection(sqlite3.Connection):
    def __exit__(self, exc_type: object, exc: object, traceback: object) -> bool:
        try:
            return bool(super().__exit__(exc_type, exc, traceback))
        finally:
            self.close()


class MonitoringStore:
    """Filesystem-backed outbox/inbox state for telemetry and SIEM delivery."""

    SCHEMA_VERSION = 1

    def __init__(self, database: str | Path) -> None:
        self.database = str(database)
        if self.database == ":memory:":
            raise ValidationError("monitoring runtime requires filesystem-backed SQLite")
        Path(self.database).parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS monitoring_schema (
                  singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                  schema_version INTEGER NOT NULL CHECK(schema_version > 0)
                );
                INSERT OR IGNORE INTO monitoring_schema VALUES(1, 1);

                CREATE TABLE IF NOT EXISTS telemetry_envelope (
                  envelope_id TEXT PRIMARY KEY,
                  event_id TEXT NOT NULL,
                  signal TEXT NOT NULL CHECK(signal IN ('logs','metrics','traces')),
                  service_name TEXT NOT NULL,
                  tenant_id TEXT NOT NULL,
                  project_id TEXT NOT NULL,
                  trace_id TEXT NOT NULL CHECK(length(trace_id)=32),
                  correlation_id TEXT NOT NULL,
                  payload_digest TEXT NOT NULL CHECK(length(payload_digest)=64),
                  payload_json BLOB NOT NULL,
                  state TEXT NOT NULL CHECK(state IN ('PENDING','DELIVERING','DELIVERED','FAILED','UNKNOWN')),
                  attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
                  claim_token TEXT,
                  lease_until TEXT,
                  response_status INTEGER,
                  response_digest TEXT,
                  last_error_class TEXT,
                  created_at TEXT NOT NULL,
                  last_attempt_at TEXT,
                  delivered_at TEXT,
                  UNIQUE(service_name, event_id, signal)
                );
                CREATE INDEX IF NOT EXISTS telemetry_delivery_queue
                  ON telemetry_envelope(state, created_at, envelope_id);

                CREATE TABLE IF NOT EXISTS siem_event (
                  event_id TEXT PRIMARY KEY,
                  source TEXT NOT NULL,
                  tenant_id TEXT NOT NULL,
                  project_id TEXT NOT NULL,
                  event_type TEXT NOT NULL,
                  actor TEXT NOT NULL,
                  trace_id TEXT NOT NULL CHECK(length(trace_id)=32),
                  correlation_id TEXT NOT NULL,
                  observed_at TEXT NOT NULL,
                  payload_digest TEXT NOT NULL CHECK(length(payload_digest)=64),
                  details_json BLOB NOT NULL,
                  signed_record_json BLOB NOT NULL,
                  ingested_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS siem_actor_event_window
                  ON siem_event(tenant_id, event_type, actor, observed_at);

                CREATE TABLE IF NOT EXISTS siem_alert (
                  alert_id TEXT PRIMARY KEY,
                  event_id TEXT NOT NULL REFERENCES siem_event(event_id),
                  tenant_id TEXT NOT NULL,
                  rule_id TEXT NOT NULL,
                  severity TEXT NOT NULL CHECK(severity IN ('low','medium','high','critical')),
                  actor TEXT NOT NULL,
                  responses_json BLOB NOT NULL,
                  alert_digest TEXT NOT NULL CHECK(length(alert_digest)=64),
                  state TEXT NOT NULL CHECK(state IN ('PENDING_EXPORT','EXPORTING','EXPORTED','EXPORT_FAILED','EXPORT_UNKNOWN')),
                  attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
                  claim_token TEXT,
                  lease_until TEXT,
                  exporter_identity TEXT,
                  receipt_digest TEXT,
                  response_json BLOB,
                  last_error_class TEXT,
                  created_at TEXT NOT NULL,
                  exported_at TEXT,
                  UNIQUE(event_id, rule_id)
                );
                CREATE INDEX IF NOT EXISTS siem_alert_export_queue
                  ON siem_alert(state, created_at, alert_id);
                """
            )
            version = connection.execute(
                "SELECT schema_version FROM monitoring_schema WHERE singleton=1"
            ).fetchone()
            if version is None or int(version[0]) != self.SCHEMA_VERSION:
                raise ValidationError("monitoring database schema version mismatch")

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.database,
            timeout=10,
            isolation_level=None,
            factory=_ClosingConnection,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=10000")
        connection.execute("PRAGMA journal_mode=WAL")
        return connection

    def enqueue_telemetry(
        self,
        *,
        event_id: str,
        service_name: str,
        tenant_id: str,
        project_id: str,
        trace_id: str,
        correlation_id: str,
        envelopes: Mapping[str, Mapping[str, Any]],
        now: datetime,
    ) -> tuple[str, ...]:
        if set(envelopes) != _SIGNALS:
            raise ValidationError("telemetry bundle must contain logs, metrics, and traces")
        created_at = _instant(now)
        identifiers: list[str] = []
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                for signal in sorted(envelopes):
                    payload = canonical_json(envelopes[signal])
                    digest = hashlib.sha256(payload).hexdigest()
                    envelope_id = sha256_json(
                        {
                            "eventId": event_id,
                            "serviceName": service_name,
                            "signal": signal,
                        }
                    )
                    prior = connection.execute(
                        "SELECT payload_digest FROM telemetry_envelope WHERE envelope_id=?",
                        (envelope_id,),
                    ).fetchone()
                    if prior is not None:
                        if prior["payload_digest"] != digest:
                            raise ValidationError("telemetry event id reused with different payload")
                    else:
                        connection.execute(
                            "INSERT INTO telemetry_envelope("
                            "envelope_id,event_id,signal,service_name,tenant_id,project_id,"
                            "trace_id,correlation_id,payload_digest,payload_json,state,created_at"
                            ") VALUES(?,?,?,?,?,?,?,?,?,?,'PENDING',?)",
                            (
                                envelope_id,
                                event_id,
                                signal,
                                service_name,
                                tenant_id,
                                project_id,
                                trace_id,
                                correlation_id,
                                digest,
                                payload,
                                created_at,
                            ),
                        )
                    identifiers.append(envelope_id)
                connection.commit()
            except BaseException:
                connection.rollback()
                raise
        return tuple(identifiers)

    def telemetry_records(self, event_id: str | None = None) -> tuple[dict[str, Any], ...]:
        query = "SELECT * FROM telemetry_envelope"
        values: tuple[object, ...] = ()
        if event_id is not None:
            query += " WHERE event_id=?"
            values = (event_id,)
        query += " ORDER BY signal,envelope_id"
        with self.connect() as connection:
            rows = connection.execute(query, values).fetchall()
        return tuple({**dict(row), "payload": json.loads(bytes(row["payload_json"]))} for row in rows)

    def claim_telemetry(
        self,
        worker_id: str,
        *,
        limit: int,
        lease_seconds: int,
        now: datetime,
    ) -> tuple[dict[str, Any], ...]:
        worker = _identifier(worker_id, "telemetry worker_id")
        bounded_limit = _bounded_int(limit, "telemetry claim limit", 1, 1000)
        lease = _bounded_int(lease_seconds, "telemetry lease_seconds", 5, 300)
        current = _utc(now)
        lease_until = _instant(current + timedelta(seconds=lease))
        claimed: list[dict[str, Any]] = []
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                # A crashed exporter does not silently retry an uncertain call.
                connection.execute(
                    "UPDATE telemetry_envelope SET state='UNKNOWN',claim_token=NULL,lease_until=NULL,"
                    "last_error_class='export_lease_expired' "
                    "WHERE state='DELIVERING' AND lease_until<=?",
                    (_instant(current),),
                )
                rows = connection.execute(
                    "SELECT * FROM telemetry_envelope WHERE state='PENDING' "
                    "ORDER BY created_at,envelope_id LIMIT ?",
                    (bounded_limit,),
                ).fetchall()
                for row in rows:
                    token = sha256_json(
                        {
                            "worker": worker,
                            "envelopeId": row["envelope_id"],
                            "attempt": int(row["attempts"]) + 1,
                            "claimedAt": _instant(current),
                        }
                    )
                    changed = connection.execute(
                        "UPDATE telemetry_envelope SET state='DELIVERING',attempts=attempts+1,"
                        "claim_token=?,lease_until=?,last_attempt_at=? "
                        "WHERE envelope_id=? AND state='PENDING'",
                        (token, lease_until, _instant(current), row["envelope_id"]),
                    ).rowcount
                    if changed == 1:
                        item = dict(row)
                        item["claim_token"] = token
                        item["attempts"] = int(row["attempts"]) + 1
                        item["payload"] = json.loads(bytes(row["payload_json"]))
                        claimed.append(item)
                connection.commit()
            except BaseException:
                connection.rollback()
                raise
        return tuple(claimed)

    def complete_telemetry(
        self,
        envelope_id: str,
        claim_token: str,
        response: "HttpExportResponse",
        *,
        now: datetime,
    ) -> None:
        if not 200 <= response.status_code < 300:
            raise ValidationError("only a successful HTTP response can complete telemetry")
        with self.connect() as connection:
            changed = connection.execute(
                "UPDATE telemetry_envelope SET state='DELIVERED',claim_token=NULL,lease_until=NULL,"
                "response_status=?,response_digest=?,last_error_class=NULL,delivered_at=? "
                "WHERE envelope_id=? AND state='DELIVERING' AND claim_token=?",
                (
                    response.status_code,
                    response.response_digest,
                    _instant(now),
                    envelope_id,
                    claim_token,
                ),
            ).rowcount
        if changed != 1:
            raise ValidationError("telemetry delivery claim is stale")

    def fail_telemetry(
        self,
        envelope_id: str,
        claim_token: str,
        *,
        state: str,
        error_class: str,
        response_status: int | None = None,
        response_digest: str | None = None,
    ) -> None:
        if state not in {"FAILED", "UNKNOWN"}:
            raise ValidationError("telemetry failure state is invalid")
        safe_error = _identifier(error_class, "telemetry error class")
        with self.connect() as connection:
            changed = connection.execute(
                "UPDATE telemetry_envelope SET state=?,claim_token=NULL,lease_until=NULL,"
                "response_status=?,response_digest=?,last_error_class=? "
                "WHERE envelope_id=? AND state='DELIVERING' AND claim_token=?",
                (
                    state,
                    response_status,
                    response_digest,
                    safe_error,
                    envelope_id,
                    claim_token,
                ),
            ).rowcount
        if changed != 1:
            raise ValidationError("telemetry delivery claim is stale")

    def retry_telemetry(
        self,
        envelope_id: str,
        claim_token: str,
        *,
        error_class: str,
        response_status: int,
        response_digest: str,
    ) -> None:
        """Return a known-rejected transient HTTP call to the bounded queue."""

        safe_error = _identifier(error_class, "telemetry error class")
        with self.connect() as connection:
            changed = connection.execute(
                "UPDATE telemetry_envelope SET state='PENDING',claim_token=NULL,lease_until=NULL,"
                "response_status=?,response_digest=?,last_error_class=? "
                "WHERE envelope_id=? AND state='DELIVERING' AND claim_token=?",
                (
                    response_status,
                    response_digest,
                    safe_error,
                    envelope_id,
                    claim_token,
                ),
            ).rowcount
        if changed != 1:
            raise ValidationError("telemetry delivery claim is stale")


@dataclass(frozen=True)
class HttpExportResponse:
    status_code: int
    response_digest: str
    response_json: Mapping[str, Any] | None = None


class TelemetryExporter(Protocol):
    def export(
        self, signal: str, envelope_id: str, payload: Mapping[str, Any]
    ) -> HttpExportResponse: ...


class _AuthenticatedHttpClient:
    def __init__(
        self,
        endpoint: str,
        bearer_token: str,
        *,
        timeout_seconds: int = 5,
        allow_insecure_loopback: bool = False,
        ca_file: str | None = None,
    ) -> None:
        parsed = urlsplit(require_text(endpoint, "export endpoint"))
        if (
            parsed.scheme not in {"http", "https"}
            or parsed.hostname is None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
        ):
            raise ValidationError("export endpoint must be an origin-only HTTP(S) URL")
        token = require_text(bearer_token, "export bearer token")
        if len(token) < 24 or len(token) > 4096 or any(ch.isspace() for ch in token):
            raise ValidationError("export bearer token is outside the safe bound")
        try:
            address = ipaddress.ip_address(parsed.hostname)
        except ValueError:
            address = None
        if parsed.scheme != "https" and not (
            allow_insecure_loopback and address is not None and address.is_loopback
        ):
            raise ValidationError("production export requires TLS")
        if parsed.port is None:
            port = 443 if parsed.scheme == "https" else 80
        else:
            port = parsed.port
        self.scheme = parsed.scheme
        self.host = parsed.hostname
        self.port = port
        self.token = token
        self.timeout = _bounded_int(timeout_seconds, "export timeout_seconds", 1, 30)
        self.context = ssl.create_default_context(cafile=ca_file) if self.scheme == "https" else None

    def post(
        self,
        path: str,
        payload: Mapping[str, Any],
        *,
        request_id: str,
        require_json_response: bool,
    ) -> HttpExportResponse:
        body = canonical_json(payload)
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "elmpay-monitoring-runtime/1",
            "X-Elmpay-Request-Id": request_id,
            "Content-Length": str(len(body)),
        }
        connection: http.client.HTTPConnection
        if self.scheme == "https":
            connection = http.client.HTTPSConnection(
                self.host, self.port, timeout=self.timeout, context=self.context
            )
        else:
            connection = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
        try:
            connection.request("POST", path, body=body, headers=headers)
            response = connection.getresponse()
            response_body = response.read(65_537)
            if len(response_body) > 65_536:
                raise ValidationError("export response exceeds the safe bound")
            digest = hashlib.sha256(response_body).hexdigest()
            parsed: Mapping[str, Any] | None = None
            if response_body:
                try:
                    value = json.loads(response_body)
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    if require_json_response or 200 <= response.status < 300:
                        raise ValidationError("export response is not valid JSON") from exc
                else:
                    parsed = require_mapping(value, "export response")
            elif require_json_response:
                raise ValidationError("export response body is required")
            return HttpExportResponse(int(response.status), digest, parsed)
        finally:
            connection.close()


class AuthenticatedOtlpHttpExporter:
    """OTLP HTTP/JSON exporter with explicit authentication and no redirects."""

    def __init__(
        self,
        endpoint: str,
        bearer_token: str,
        *,
        timeout_seconds: int = 5,
        allow_insecure_loopback: bool = False,
        ca_file: str | None = None,
    ) -> None:
        self.client = _AuthenticatedHttpClient(
            endpoint,
            bearer_token,
            timeout_seconds=timeout_seconds,
            allow_insecure_loopback=allow_insecure_loopback,
            ca_file=ca_file,
        )

    def export(
        self, signal: str, envelope_id: str, payload: Mapping[str, Any]
    ) -> HttpExportResponse:
        if signal not in _SIGNALS:
            raise ValidationError("unknown OTLP signal")
        return self.client.post(
            _OTLP_PATH[signal], payload, request_id=envelope_id, require_json_response=False
        )


@dataclass(frozen=True)
class ServiceOperationContext:
    event_id: str
    tenant_id: str
    project_id: str
    trace_id: str
    span_id: str
    correlation_id: str
    operation: str
    baggage: Mapping[str, str]


ServiceResult = TypeVar("ServiceResult")


class ServiceTelemetryAdapter:
    """Wrap a real service operation and durably observe success or failure."""

    def __init__(
        self,
        store: MonitoringStore,
        *,
        service_name: str,
        service_version: str,
        environment: str,
        clock: Callable[[], datetime] | None = None,
        monotonic_ns: Callable[[], int] | None = None,
    ) -> None:
        self.store = store
        self.service_name = _identifier(service_name, "service_name")
        self.service_version = _identifier(service_version, "service_version")
        normalized_environment = require_text(environment, "environment").upper()
        if normalized_environment not in {"TEST", "STAGING", "PRODUCTION"}:
            raise ValidationError("environment must be TEST, STAGING, or PRODUCTION")
        self.environment = normalized_environment
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.monotonic_ns = monotonic_ns or time.monotonic_ns

    def invoke(
        self,
        context: ServiceOperationContext,
        handler: Callable[[], ServiceResult],
        *,
        attributes: Mapping[str, Any] | None = None,
    ) -> ServiceResult:
        started = self.monotonic_ns()
        try:
            value = handler()
        except BaseException:
            duration = max(0, (self.monotonic_ns() - started) // 1_000_000)
            self.record_operation(
                context,
                outcome="FAILED",
                duration_ms=int(duration),
                attributes={**dict(attributes or {}), "exception.escaped": True},
                observed_at=self.clock(),
            )
            raise
        duration = max(0, (self.monotonic_ns() - started) // 1_000_000)
        self.record_operation(
            context,
            outcome="SUCCEEDED",
            duration_ms=int(duration),
            attributes=attributes or {},
            observed_at=self.clock(),
        )
        return value

    def record_operation(
        self,
        context: ServiceOperationContext,
        *,
        outcome: str,
        duration_ms: int,
        attributes: Mapping[str, Any],
        observed_at: datetime,
    ) -> tuple[str, ...]:
        event_id = _identifier(context.event_id, "event_id")
        tenant_id = _identifier(context.tenant_id, "tenant_id")
        project_id = _identifier(context.project_id, "project_id")
        trace_hex = require_text(context.trace_id, "trace_id")
        span_hex = require_text(context.span_id, "span_id")
        trace_b64 = _trace_bytes(trace_hex, "trace_id", _TRACE)
        span_b64 = _trace_bytes(span_hex, "span_id", _SPAN)
        correlation_id = _identifier(context.correlation_id, "correlation_id")
        operation = _identifier(context.operation, "operation")
        bounded_duration = _bounded_int(duration_ms, "duration_ms", 0, 86_400_000)
        current = _utc(observed_at)
        record = telemetry_record(
            tenant_id=tenant_id,
            project_id=project_id,
            trace_id=trace_hex,
            correlation_id=correlation_id,
            operation=operation,
            outcome=outcome,
            attributes=attributes,
            baggage=context.baggage,
        )
        binding_attributes: dict[str, Any] = {
            "tenant.id": tenant_id,
            "project.id": project_id,
            "elmpay.correlation_id": correlation_id,
            "elmpay.operation": operation,
            "elmpay.outcome": outcome,
            **{f"baggage.{key}": value for key, value in record["baggage"].items()},
            **{f"app.{key}": value for key, value in record["attributes"].items()},
        }
        resource = {
            "attributes": _otlp_attributes(
                {
                    "service.name": self.service_name,
                    "service.version": self.service_version,
                    "deployment.environment.name": self.environment.lower(),
                    "tenant.id": tenant_id,
                    "project.id": project_id,
                }
            )
        }
        scope = {"name": "com.elmpay.service-runtime", "version": "1.0.0"}
        end_nano = int(_unix_nano(current))
        start_nano = max(0, end_nano - bounded_duration * 1_000_000)
        envelopes: dict[str, Mapping[str, Any]] = {
            "logs": {
                "resourceLogs": [
                    {
                        "resource": resource,
                        "scopeLogs": [
                            {
                                "scope": scope,
                                "logRecords": [
                                    {
                                        "timeUnixNano": str(end_nano),
                                        "observedTimeUnixNano": str(end_nano),
                                        "severityNumber": 9 if outcome == "SUCCEEDED" else 17,
                                        "severityText": "INFO" if outcome == "SUCCEEDED" else "ERROR",
                                        "body": _otlp_value(
                                            {
                                                "eventId": event_id,
                                                "operation": operation,
                                                "outcome": outcome,
                                            }
                                        ),
                                        "attributes": _otlp_attributes(binding_attributes),
                                        "traceId": trace_b64,
                                        "spanId": span_b64,
                                    }
                                ],
                            }
                        ],
                    }
                ]
            },
            "traces": {
                "resourceSpans": [
                    {
                        "resource": resource,
                        "scopeSpans": [
                            {
                                "scope": scope,
                                "spans": [
                                    {
                                        "traceId": trace_b64,
                                        "spanId": span_b64,
                                        "name": operation,
                                        "kind": 2,
                                        "startTimeUnixNano": str(start_nano),
                                        "endTimeUnixNano": str(end_nano),
                                        "attributes": _otlp_attributes(binding_attributes),
                                        "status": {
                                            "code": 1 if outcome == "SUCCEEDED" else 2,
                                            "message": "" if outcome == "SUCCEEDED" else "operation_failed",
                                        },
                                    }
                                ],
                            }
                        ],
                    }
                ]
            },
            "metrics": {
                "resourceMetrics": [
                    {
                        "resource": resource,
                        "scopeMetrics": [
                            {
                                "scope": scope,
                                "metrics": [
                                    {
                                        "name": "elmpay.operation.duration",
                                        "unit": "ms",
                                        "gauge": {
                                            "dataPoints": [
                                                {
                                                    "timeUnixNano": str(end_nano),
                                                    "asInt": str(bounded_duration),
                                                    "attributes": _otlp_attributes(binding_attributes),
                                                }
                                            ]
                                        },
                                    },
                                    {
                                        "name": "elmpay.operation.calls",
                                        "unit": "1",
                                        "sum": {
                                            "aggregationTemporality": 1,
                                            "isMonotonic": True,
                                            "dataPoints": [
                                                {
                                                    "startTimeUnixNano": str(start_nano),
                                                    "timeUnixNano": str(end_nano),
                                                    "asInt": "1",
                                                    "attributes": _otlp_attributes(binding_attributes),
                                                }
                                            ],
                                        },
                                    },
                                ],
                            }
                        ],
                    }
                ]
            },
        }
        return self.store.enqueue_telemetry(
            event_id=event_id,
            service_name=self.service_name,
            tenant_id=tenant_id,
            project_id=project_id,
            trace_id=trace_hex,
            correlation_id=correlation_id,
            envelopes=envelopes,
            now=current,
        )

    def export_pending(
        self,
        exporter: TelemetryExporter,
        *,
        worker_id: str,
        limit: int = 100,
        lease_seconds: int = 30,
        maximum_attempts: int = 3,
        now: datetime | None = None,
    ) -> dict[str, int]:
        current = _utc(now)
        attempts_limit = _bounded_int(
            maximum_attempts, "telemetry maximum_attempts", 1, 10
        )
        claimed = self.store.claim_telemetry(
            worker_id, limit=limit, lease_seconds=lease_seconds, now=current
        )
        summary = {
            "claimed": len(claimed),
            "delivered": 0,
            "retryPending": 0,
            "failed": 0,
            "unknown": 0,
        }
        for row in claimed:
            try:
                response = exporter.export(row["signal"], row["envelope_id"], row["payload"])
            except BaseException as exc:
                self.store.fail_telemetry(
                    row["envelope_id"],
                    row["claim_token"],
                    state="UNKNOWN",
                    error_class=type(exc).__name__,
                )
                summary["unknown"] += 1
                continue
            if 200 <= response.status_code < 300:
                self.store.complete_telemetry(
                    row["envelope_id"], row["claim_token"], response, now=current
                )
                summary["delivered"] += 1
            elif (
                response.status_code in {408, 425, 429}
                or 500 <= response.status_code < 600
            ) and int(row["attempts"]) < attempts_limit:
                self.store.retry_telemetry(
                    row["envelope_id"],
                    row["claim_token"],
                    error_class=f"http_{response.status_code}",
                    response_status=response.status_code,
                    response_digest=response.response_digest,
                )
                summary["retryPending"] += 1
            else:
                self.store.fail_telemetry(
                    row["envelope_id"],
                    row["claim_token"],
                    state="FAILED",
                    error_class=f"http_{response.status_code}",
                    response_status=response.status_code,
                    response_digest=response.response_digest,
                )
                summary["failed"] += 1
        return summary


def siem_event_binding(event: Mapping[str, Any]) -> str:
    semantic_fields = (
        "schemaVersion",
        "eventId",
        "source",
        "eventType",
        "tenantId",
        "projectId",
        "actor",
        "observedAt",
        "traceId",
        "correlationId",
        "details",
    )
    document = {field: event.get(field) for field in semantic_fields}
    return sha256_json(document)


@dataclass(frozen=True)
class SiemIngestionResult:
    event_id: str
    duplicate: bool
    alert_ids: tuple[str, ...]
    signer_identity: str


class SiemAlertExporter(Protocol):
    def export(self, alert: Mapping[str, Any]) -> Mapping[str, Any]: ...


class AuthenticatedSiemHttpExporter:
    """Send one alert and return the downstream system's signed receipt."""

    def __init__(
        self,
        endpoint: str,
        bearer_token: str,
        *,
        timeout_seconds: int = 5,
        allow_insecure_loopback: bool = False,
        ca_file: str | None = None,
    ) -> None:
        self.client = _AuthenticatedHttpClient(
            endpoint,
            bearer_token,
            timeout_seconds=timeout_seconds,
            allow_insecure_loopback=allow_insecure_loopback,
            ca_file=ca_file,
        )

    def export(self, alert: Mapping[str, Any]) -> Mapping[str, Any]:
        alert_id = require_text(alert.get("alertId"), "alertId")
        response = self.client.post(
            "/api/v1/alerts",
            alert,
            request_id=alert_id,
            require_json_response=True,
        )
        if not 200 <= response.status_code < 300 or response.response_json is None:
            raise ValidationError(f"SIEM exporter returned HTTP {response.status_code}")
        return response.response_json


class DurableSiemService:
    """Trusted SIEM event inbox, durable detector and signed-receipt outbox."""

    _BASE_FIELDS = frozenset(
        {
            "schemaVersion",
            "eventId",
            "source",
            "eventType",
            "tenantId",
            "projectId",
            "actor",
            "role",
            "observedAt",
            "traceId",
            "correlationId",
            "details",
            "bindingDigest",
            "nonce",
            "issuedAt",
            "expiresAt",
            "dsse",
        }
    )

    def __init__(
        self,
        store: MonitoringStore,
        *,
        runtime_policy: Mapping[str, Any],
        detection_policy: Mapping[str, Any],
        source_trust: Mapping[str, Any],
        receipt_trust: Mapping[str, Any] | None = None,
    ) -> None:
        self.store = store
        self.policy = dict(require_mapping(runtime_policy, "SIEM runtime policy"))
        self.detection_policy = dict(require_mapping(detection_policy, "SIEM detection policy"))
        self.source_trust = dict(require_mapping(source_trust, "SIEM source trust"))
        self.receipt_trust = (
            dict(require_mapping(receipt_trust, "SIEM receipt trust"))
            if receipt_trust is not None
            else None
        )
        if self.policy.get("schemaVersion") != 1:
            raise ValidationError("SIEM runtime policy schemaVersion must be 1")
        if self.policy.get("requiredSourceRole") != "siem_event_source":
            raise ValidationError("SIEM sources must use the siem_event_source role")
        require_mapping(self.policy.get("sources"), "SIEM sources")
        exporter_policy = require_mapping(self.policy.get("exporter"), "SIEM exporter policy")
        if (
            exporter_policy.get("receiptRole") != "siem_exporter"
            or exporter_policy.get("receiptMustBeIndependent") is not True
        ):
            raise ValidationError(
                "SIEM export requires an independent siem_exporter receipt"
            )
        self.nonces = nonce_store_from_trust(self.source_trust)

    def ingest(
        self, raw_event: Mapping[str, Any], *, now: datetime | None = None
    ) -> SiemIngestionResult:
        current = _utc(now)
        event = dict(require_mapping(raw_event, "SIEM event"))
        if set(event) != self._BASE_FIELDS:
            raise ValidationError("SIEM event fields do not match schema version 1")
        if event.get("schemaVersion") != 1:
            raise ValidationError("SIEM event schemaVersion must be 1")
        event_id = _identifier(event.get("eventId"), "eventId")
        source = _identifier(event.get("source"), "source")
        event_type = _identifier(event.get("eventType"), "eventType")
        tenant_id = _identifier(event.get("tenantId"), "tenantId")
        project_id = _identifier(event.get("projectId"), "projectId")
        source_identity = _identifier(event.get("actor"), "actor")
        trace_id = require_text(event.get("traceId"), "traceId")
        _trace_bytes(trace_id, "traceId", _TRACE)
        correlation_id = _identifier(event.get("correlationId"), "correlationId")
        details = dict(require_mapping(event.get("details"), "details"))
        observed_at = parse_instant(event.get("observedAt"), "observedAt")
        maximum_age = _bounded_int(
            self.policy.get("maximumEventAgeSeconds"),
            "maximumEventAgeSeconds",
            1,
            86_400,
        )
        maximum_future = _bounded_int(
            self.policy.get("maximumFutureSkewSeconds"),
            "maximumFutureSkewSeconds",
            0,
            300,
        )
        if observed_at > current + timedelta(seconds=maximum_future):
            raise ValidationError("SIEM event is in the future")
        if current - observed_at > timedelta(seconds=maximum_age):
            raise ValidationError("SIEM event is stale")
        sources = require_mapping(self.policy.get("sources"), "SIEM sources")
        source_policy = require_mapping(sources.get(source), f"SIEM source {source}")
        identities = set(require_list(source_policy.get("identities"), "source identities"))
        if not identities:
            raise ValidationError("SIEM source has no trusted identities")
        event_schemas = require_mapping(source_policy.get("eventTypes"), "source eventTypes")
        event_policy = require_mapping(event_schemas.get(event_type), f"event type {event_type}")
        self._validate_details(event_type, details, event_policy)
        subject_actor = _identifier(
            details.get("subjectActor", source_identity), "details.subjectActor"
        )
        safe = telemetry_record(
            tenant_id=tenant_id,
            project_id=project_id,
            trace_id=trace_id,
            correlation_id=correlation_id,
            operation=event_type,
            outcome="PENDING",
            attributes=details,
        )["attributes"]
        if safe != details:
            raise ValidationError("SIEM event details contain sensitive data")
        binding = siem_event_binding(event)
        signer = verify_dsse_record(
            event,
            self.source_trust,
            binding,
            now=current,
            nonce_store=self.nonces,
        )
        if signer.role != "siem_event_source":
            raise ValidationError("SIEM event signer role mismatch")
        if signer.identity not in identities or source_identity != signer.identity:
            raise ValidationError("SIEM source identity mismatch")

        encoded = canonical_json(event)
        with self.store.connect() as connection:
            prior = connection.execute(
                "SELECT payload_digest FROM siem_event WHERE event_id=?", (event_id,)
            ).fetchone()
            if prior is not None:
                if prior["payload_digest"] != signer.payload_digest:
                    raise ValidationError("SIEM event id reused with different signed payload")
                alert_ids = tuple(
                    row[0]
                    for row in connection.execute(
                        "SELECT alert_id FROM siem_alert WHERE event_id=? ORDER BY alert_id",
                        (event_id,),
                    ).fetchall()
                )
                return SiemIngestionResult(event_id, True, alert_ids, signer.identity)

        normalized = {"eventType": event_type, "actor": subject_actor, **details}
        evaluation_events: list[Mapping[str, Any]] = []
        if event_type == "admin.authentication.succeeded":
            window = observed_at - timedelta(minutes=30)
            with self.store.connect() as connection:
                rows = connection.execute(
                    "SELECT details_json FROM siem_event WHERE tenant_id=? AND event_type=? "
                    "AND actor=? AND observed_at>=? AND observed_at<=? ORDER BY observed_at,event_id",
                    (
                        tenant_id,
                        event_type,
                        subject_actor,
                        window.isoformat(),
                        observed_at.isoformat(),
                    ),
                ).fetchall()
            evaluation_events.extend(
                {"eventType": event_type, "actor": subject_actor, **json.loads(bytes(row[0]))}
                for row in rows
            )
        evaluation_events.append(normalized)
        alerts = list(evaluate_security_events(self.detection_policy, evaluation_events))
        if not alerts and event_policy.get("disposition") == "ALERT":
            severity = require_text(event_policy.get("severity"), "default alert severity")
            responses = tuple(
                require_text(item, "default alert response")
                for item in require_list(event_policy.get("response"), "default alert responses")
            )
            alerts.append(
                SecurityAlert(
                    f"SIEM-SOURCE-{source.upper().replace('-', '_')}",
                    severity,
                    subject_actor,
                    responses,
                )
            )
        ingested_at = _instant(current)
        created_alert_ids: list[str] = []
        with self.store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                connection.execute(
                    "INSERT INTO siem_event VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        event_id,
                        source,
                        tenant_id,
                        project_id,
                        event_type,
                        subject_actor,
                        trace_id,
                        correlation_id,
                        observed_at.isoformat(),
                        signer.payload_digest,
                        canonical_json(details),
                        encoded,
                        ingested_at,
                    ),
                )
                for alert in alerts:
                    if alert.severity not in {"low", "medium", "high", "critical"}:
                        raise ValidationError("SIEM alert severity is invalid")
                    document = {
                        "eventId": event_id,
                        "tenantId": tenant_id,
                        "ruleId": alert.rule_id,
                        "severity": alert.severity,
                        "actor": alert.actor,
                        "responses": list(alert.responses),
                    }
                    alert_digest = sha256_json(document)
                    alert_id = sha256_json(
                        {"eventId": event_id, "ruleId": alert.rule_id}
                    )
                    connection.execute(
                        "INSERT INTO siem_alert("
                        "alert_id,event_id,tenant_id,rule_id,severity,actor,responses_json,"
                        "alert_digest,state,created_at"
                        ") VALUES(?,?,?,?,?,?,?,?,'PENDING_EXPORT',?)",
                        (
                            alert_id,
                            event_id,
                            tenant_id,
                            alert.rule_id,
                            alert.severity,
                            alert.actor,
                            canonical_json(list(alert.responses)),
                            alert_digest,
                            ingested_at,
                        ),
                    )
                    created_alert_ids.append(alert_id)
                connection.commit()
            except sqlite3.IntegrityError as exc:
                connection.rollback()
                # Another worker may have committed the exact signed event while
                # this worker evaluated it. Treat only byte-identical signed
                # input as the same idempotent operation.
                with self.store.connect() as existing_connection:
                    existing = existing_connection.execute(
                        "SELECT payload_digest FROM siem_event WHERE event_id=?",
                        (event_id,),
                    ).fetchone()
                    alert_ids = tuple(
                        row[0]
                        for row in existing_connection.execute(
                            "SELECT alert_id FROM siem_alert WHERE event_id=? ORDER BY alert_id",
                            (event_id,),
                        ).fetchall()
                    )
                if existing is not None and existing["payload_digest"] == signer.payload_digest:
                    return SiemIngestionResult(
                        event_id, True, alert_ids, signer.identity
                    )
                raise ValidationError("concurrent SIEM event id collision") from exc
            except BaseException:
                connection.rollback()
                raise
        return SiemIngestionResult(
            event_id, False, tuple(sorted(created_alert_ids)), signer.identity
        )

    @staticmethod
    def _validate_details(
        event_type: str, details: Mapping[str, Any], policy: Mapping[str, Any]
    ) -> None:
        required = set(require_list(policy.get("requiredFields"), "requiredFields"))
        allowed = set(require_list(policy.get("allowedFields"), "allowedFields"))
        if not required <= allowed or set(details) != allowed:
            raise ValidationError(f"{event_type} detail fields do not match the governed schema")
        types = require_mapping(policy.get("fieldTypes"), "fieldTypes")
        if set(types) != allowed:
            raise ValidationError("SIEM event field type schema is incomplete")
        for field in sorted(allowed):
            value = details[field]
            expected = types[field]
            if expected == "string":
                _identifier(value, f"details.{field}")
            elif expected == "country_code":
                text = require_text(value, f"details.{field}")
                if not re.fullmatch(r"[A-Z]{2}", text):
                    raise ValidationError(f"details.{field} is not an ISO country code")
            elif expected == "boolean":
                if not isinstance(value, bool):
                    raise ValidationError(f"details.{field} must be boolean")
            elif expected == "nonnegative_integer":
                _bounded_int(value, f"details.{field}", 0, 10**12)
            else:
                raise ValidationError(f"unsupported SIEM field type: {expected}")

    def alerts(self, event_id: str | None = None) -> tuple[dict[str, Any], ...]:
        query = "SELECT * FROM siem_alert"
        values: tuple[object, ...] = ()
        if event_id is not None:
            query += " WHERE event_id=?"
            values = (event_id,)
        query += " ORDER BY created_at,alert_id"
        with self.store.connect() as connection:
            rows = connection.execute(query, values).fetchall()
        return tuple(
            {
                **dict(row),
                "responses": json.loads(bytes(row["responses_json"])),
                "response": json.loads(bytes(row["response_json"]))
                if row["response_json"] is not None
                else None,
            }
            for row in rows
        )

    def _claim_alerts(
        self,
        worker_id: str,
        *,
        limit: int,
        lease_seconds: int,
        now: datetime,
    ) -> tuple[dict[str, Any], ...]:
        worker = _identifier(worker_id, "SIEM exporter worker_id")
        bounded_limit = _bounded_int(limit, "SIEM export limit", 1, 1000)
        lease = _bounded_int(lease_seconds, "SIEM export lease", 5, 300)
        current = _utc(now)
        claimed: list[dict[str, Any]] = []
        with self.store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                connection.execute(
                    "UPDATE siem_alert SET state='EXPORT_UNKNOWN',claim_token=NULL,lease_until=NULL,"
                    "last_error_class='export_lease_expired' "
                    "WHERE state='EXPORTING' AND lease_until<=?",
                    (_instant(current),),
                )
                rows = connection.execute(
                    "SELECT * FROM siem_alert WHERE state='PENDING_EXPORT' "
                    "ORDER BY created_at,alert_id LIMIT ?",
                    (bounded_limit,),
                ).fetchall()
                for row in rows:
                    token = sha256_json(
                        {
                            "worker": worker,
                            "alertId": row["alert_id"],
                            "attempt": int(row["attempts"]) + 1,
                            "claimedAt": _instant(current),
                        }
                    )
                    changed = connection.execute(
                        "UPDATE siem_alert SET state='EXPORTING',attempts=attempts+1,"
                        "claim_token=?,lease_until=? WHERE alert_id=? AND state='PENDING_EXPORT'",
                        (
                            token,
                            _instant(current + timedelta(seconds=lease)),
                            row["alert_id"],
                        ),
                    ).rowcount
                    if changed == 1:
                        item = dict(row)
                        item["claim_token"] = token
                        item["attempts"] = int(row["attempts"]) + 1
                        item["responses"] = json.loads(bytes(row["responses_json"]))
                        claimed.append(item)
                connection.commit()
            except BaseException:
                connection.rollback()
                raise
        return tuple(claimed)

    def export_pending(
        self,
        exporter: SiemAlertExporter,
        *,
        destination: str,
        worker_id: str,
        limit: int = 100,
        lease_seconds: int = 30,
        now: datetime | None = None,
    ) -> dict[str, int]:
        if self.receipt_trust is None:
            raise ValidationError("SIEM receipt trust is required before export")
        configured = require_mapping(self.policy.get("exporter"), "SIEM exporter policy")
        destination_id = _identifier(destination, "SIEM destination")
        if destination_id != configured.get("destination"):
            raise ValidationError("SIEM destination does not match policy")
        current = _utc(now)
        rows = self._claim_alerts(
            worker_id, limit=limit, lease_seconds=lease_seconds, now=current
        )
        summary = {"claimed": len(rows), "exported": 0, "unknown": 0}
        for row in rows:
            alert = {
                "schemaVersion": 1,
                "alertId": row["alert_id"],
                "eventId": row["event_id"],
                "tenantId": row["tenant_id"],
                "ruleId": row["rule_id"],
                "severity": row["severity"],
                "actor": row["actor"],
                "responses": row["responses"],
                "alertDigest": row["alert_digest"],
                "destination": destination_id,
            }
            try:
                receipt = require_mapping(exporter.export(alert), "SIEM exporter receipt")
                receipt_digest, signer = verify_downstream_receipt(
                    receipt,
                    self.receipt_trust,
                    receipt_type="SIEM_ALERT",
                    outcome="ACCEPTED",
                    fields={
                        "alertId": row["alert_id"],
                        "alertDigest": row["alert_digest"],
                        "tenantId": row["tenant_id"],
                        "destination": destination_id,
                    },
                    required_role=require_text(
                        configured.get("receiptRole"), "SIEM receipt role"
                    ),
                    require_independent=configured.get("receiptMustBeIndependent") is True,
                    now=current,
                )
            except BaseException as exc:
                with self.store.connect() as connection:
                    changed = connection.execute(
                        "UPDATE siem_alert SET state='EXPORT_UNKNOWN',claim_token=NULL,"
                        "lease_until=NULL,last_error_class=? "
                        "WHERE alert_id=? AND state='EXPORTING' AND claim_token=?",
                        (type(exc).__name__, row["alert_id"], row["claim_token"]),
                    ).rowcount
                if changed != 1:
                    raise ValidationError("SIEM alert export claim is stale") from exc
                summary["unknown"] += 1
                continue
            with self.store.connect() as connection:
                changed = connection.execute(
                    "UPDATE siem_alert SET state='EXPORTED',claim_token=NULL,lease_until=NULL,"
                    "exporter_identity=?,receipt_digest=?,response_json=?,last_error_class=NULL,"
                    "exported_at=? WHERE alert_id=? AND state='EXPORTING' AND claim_token=?",
                    (
                        signer.identity,
                        receipt_digest,
                        canonical_json(receipt),
                        _instant(current),
                        row["alert_id"],
                        row["claim_token"],
                    ),
                ).rowcount
            if changed != 1:
                raise ValidationError("SIEM alert export claim is stale")
            summary["exported"] += 1
        return summary
