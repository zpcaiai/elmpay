"""Executable B88 gateway controls.

The module deliberately keeps authentication, replay protection and rate
limiting ahead of any business handler.  SQLite is the local durable adapter;
production deployments can implement the same store contract with a
transactional database without changing the decision semantics.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import ipaddress
import re
import sqlite3
from typing import Mapping, Protocol

from .common import ValidationError, canonical_json, require_text


SIGNATURE_VERSION = "ELMPAY-HMAC-SHA256-V1"
NONCE_RE = re.compile(r"^[A-Za-z0-9._:-]{16,128}$")
SAFE_PATH_RE = re.compile(r"^/v1/[A-Za-z0-9_./{}-]{1,240}$")
FORBIDDEN_BODY = re.compile(
    r"(?i)(?:<script\b|javascript:|\bunion\s+select\b|(?:^|[\s'\"])(?:or|and)\s+1\s*=\s*1)"
)


@dataclass(frozen=True)
class EdgeRequest:
    tenant_id: str
    project_id: str
    method: str
    path: str
    body: bytes
    content_type: str
    origin: str | None
    source_ip: str
    forwarded_for: str | None
    timestamp: datetime
    nonce: str
    signature: str


@dataclass(frozen=True)
class EdgeDecision:
    allowed: bool
    code: str
    effective_ip: str | None = None
    request_digest: str | None = None


class SecretResolver(Protocol):
    def resolve(self, tenant_id: str, project_id: str) -> bytes: ...


class EdgeStateStore(Protocol):
    def consume_nonce(
        self,
        tenant_id: str,
        project_id: str,
        nonce: str,
        digest: str,
        observed_at: datetime,
        expires_at: datetime,
    ) -> str: ...

    def consume_quota(
        self, scope: str, bucket: int, limit: int, expires_at: datetime
    ) -> bool: ...


class SQLiteEdgeStateStore:
    """Atomic cross-process replay and fixed-window rate-limit state."""

    def __init__(self, path: str) -> None:
        self._connection = sqlite3.connect(path, timeout=5, isolation_level=None)
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA busy_timeout=5000")
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS edge_nonce (
              tenant_id TEXT NOT NULL,
              project_id TEXT NOT NULL,
              nonce TEXT NOT NULL,
              request_digest TEXT NOT NULL,
              expires_at TEXT NOT NULL,
              PRIMARY KEY (tenant_id, project_id, nonce)
            );
            CREATE TABLE IF NOT EXISTS edge_quota (
              scope TEXT NOT NULL,
              bucket INTEGER NOT NULL,
              used INTEGER NOT NULL CHECK (used >= 0),
              expires_at TEXT NOT NULL,
              PRIMARY KEY (scope, bucket)
            );
            """
        )

    def close(self) -> None:
        self._connection.close()

    def consume_nonce(
        self,
        tenant_id: str,
        project_id: str,
        nonce: str,
        digest: str,
        observed_at: datetime,
        expires_at: datetime,
    ) -> str:
        now_text = observed_at.astimezone(timezone.utc).isoformat()
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            self._connection.execute("DELETE FROM edge_nonce WHERE expires_at <= ?", (now_text,))
            row = self._connection.execute(
                "SELECT request_digest FROM edge_nonce WHERE tenant_id=? AND project_id=? AND nonce=?",
                (tenant_id, project_id, nonce),
            ).fetchone()
            if row is None:
                self._connection.execute(
                    "INSERT INTO edge_nonce(tenant_id, project_id, nonce, request_digest, expires_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (tenant_id, project_id, nonce, digest, expires_at.isoformat()),
                )
                result = "ACCEPTED"
            elif hmac.compare_digest(str(row[0]), digest):
                result = "REPLAY"
            else:
                result = "CONFLICT"
            self._connection.execute("COMMIT")
            return result
        except Exception:
            self._connection.execute("ROLLBACK")
            raise

    def consume_quota(
        self, scope: str, bucket: int, limit: int, expires_at: datetime
    ) -> bool:
        if limit <= 0:
            raise ValidationError("rate limit must be positive")
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            self._connection.execute(
                "INSERT INTO edge_quota(scope, bucket, used, expires_at) VALUES (?, ?, 1, ?) "
                "ON CONFLICT(scope, bucket) DO UPDATE SET used=used+1",
                (scope, bucket, expires_at.isoformat()),
            )
            used = int(self._connection.execute(
                "SELECT used FROM edge_quota WHERE scope=? AND bucket=?", (scope, bucket)
            ).fetchone()[0])
            self._connection.execute("COMMIT")
            return used <= limit
        except Exception:
            self._connection.execute("ROLLBACK")
            raise


class MappingSecretResolver:
    def __init__(self, secrets: Mapping[tuple[str, str], bytes]) -> None:
        self._secrets = dict(secrets)

    def resolve(self, tenant_id: str, project_id: str) -> bytes:
        value = self._secrets.get((tenant_id, project_id))
        if value is None or len(value) < 32:
            raise ValidationError("merchant signing key unavailable")
        return value


def request_digest(request: EdgeRequest) -> str:
    body_digest = hashlib.sha256(request.body).hexdigest()
    canonical = {
        "version": SIGNATURE_VERSION,
        "tenantId": request.tenant_id,
        "projectId": request.project_id,
        "method": request.method.upper(),
        "path": request.path,
        "contentType": request.content_type.lower(),
        "bodySha256": body_digest,
        "timestamp": request.timestamp.astimezone(timezone.utc).isoformat(),
        "nonce": request.nonce,
    }
    return hashlib.sha256(canonical_json(canonical)).hexdigest()


def sign_request(request: EdgeRequest, secret: bytes) -> str:
    return hmac.new(secret, request_digest(request).encode("ascii"), hashlib.sha256).hexdigest()


class EdgeGuard:
    def __init__(
        self,
        *,
        secrets: SecretResolver,
        state: EdgeStateStore,
        allowed_origins: Mapping[str, tuple[str, ...]],
        trusted_proxy_cidrs: tuple[str, ...],
        request_limit_per_minute: int = 120,
        ip_limit_per_minute: int = 600,
        maximum_body_bytes: int = 1_048_576,
        maximum_clock_skew_seconds: int = 300,
    ) -> None:
        self._secrets = secrets
        self._state = state
        self._allowed_origins = dict(allowed_origins)
        self._trusted_proxies = tuple(ipaddress.ip_network(value) for value in trusted_proxy_cidrs)
        self._tenant_limit = request_limit_per_minute
        self._ip_limit = ip_limit_per_minute
        self._maximum_body = maximum_body_bytes
        self._skew = timedelta(seconds=maximum_clock_skew_seconds)
        if not self._trusted_proxies:
            raise ValidationError("at least one explicit trusted proxy network is required")

    def authorize(self, request: EdgeRequest, *, now: datetime | None = None) -> EdgeDecision:
        current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        try:
            tenant = require_text(request.tenant_id, "tenant_id")
            project = require_text(request.project_id, "project_id")
            if request.timestamp.tzinfo is None or abs(current - request.timestamp) > self._skew:
                return EdgeDecision(False, "REQUEST_TIMESTAMP_INVALID")
            if not NONCE_RE.fullmatch(request.nonce):
                return EdgeDecision(False, "REQUEST_NONCE_INVALID")
            if request.method.upper() not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
                return EdgeDecision(False, "REQUEST_METHOD_INVALID")
            if not SAFE_PATH_RE.fullmatch(request.path) or ".." in request.path:
                return EdgeDecision(False, "REQUEST_PATH_INVALID")
            if len(request.body) > self._maximum_body:
                return EdgeDecision(False, "REQUEST_BODY_TOO_LARGE")
            if request.body and request.content_type.lower() != "application/json":
                return EdgeDecision(False, "REQUEST_CONTENT_TYPE_INVALID")
            body_text = request.body.decode("utf-8", errors="strict")
            if FORBIDDEN_BODY.search(body_text):
                return EdgeDecision(False, "WAF_INPUT_REJECTED")
            allowed = self._allowed_origins.get(tenant, ())
            if request.origin is not None and request.origin not in allowed:
                return EdgeDecision(False, "CORS_ORIGIN_DENIED")
            effective_ip = self._effective_ip(request.source_ip, request.forwarded_for)
            digest = request_digest(request)
            secret = self._secrets.resolve(tenant, project)
            expected = hmac.new(secret, digest.encode("ascii"), hashlib.sha256).hexdigest()
            if not re.fullmatch(r"[0-9a-f]{64}", request.signature) or not hmac.compare_digest(
                expected, request.signature
            ):
                return EdgeDecision(False, "REQUEST_SIGNATURE_INVALID", effective_ip, digest)
            nonce_state = self._state.consume_nonce(
                tenant, project, request.nonce, digest, current, current + self._skew
            )
            if nonce_state == "CONFLICT":
                return EdgeDecision(False, "REQUEST_NONCE_CONFLICT", effective_ip, digest)
            if nonce_state == "REPLAY":
                return EdgeDecision(False, "REQUEST_REPLAYED", effective_ip, digest)
            bucket = int(current.timestamp()) // 60
            expiry = current + timedelta(minutes=2)
            if not self._state.consume_quota(
                f"tenant:{tenant}:project:{project}", bucket, self._tenant_limit, expiry
            ):
                return EdgeDecision(False, "TENANT_RATE_LIMITED", effective_ip, digest)
            if not self._state.consume_quota(f"ip:{effective_ip}", bucket, self._ip_limit, expiry):
                return EdgeDecision(False, "SOURCE_RATE_LIMITED", effective_ip, digest)
            return EdgeDecision(True, "ALLOWED", effective_ip, digest)
        except (UnicodeDecodeError, ValueError, sqlite3.Error, ValidationError):
            return EdgeDecision(False, "EDGE_CONTROL_UNAVAILABLE")

    def _effective_ip(self, source_ip: str, forwarded_for: str | None) -> str:
        peer = ipaddress.ip_address(source_ip)
        trusted = any(peer in network for network in self._trusted_proxies)
        if not trusted or forwarded_for is None:
            return str(peer)
        chain = [ipaddress.ip_address(item.strip()) for item in forwarded_for.split(",") if item.strip()]
        if not chain:
            raise ValidationError("forwarded chain is empty")
        # Walk from the proxy side and return the first untrusted hop.  A client
        # cannot select the effective address by prepending a fake value.
        for candidate in reversed(chain):
            if not any(candidate in network for network in self._trusted_proxies):
                return str(candidate)
        raise ValidationError("forwarded chain contains only trusted proxies")
