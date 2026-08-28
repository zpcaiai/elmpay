"""Durable, fail-closed B31 cross-tenant live isolation probes."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import http.client
import json
from pathlib import Path
import re
import sqlite3
import ssl
from typing import Any, Mapping, Protocol
from urllib.parse import urlsplit
import uuid

from .common import ValidationError, canonical_json, require_mapping, require_text, sha256_json


MIGRATION = Path(__file__).resolve().parents[1] / "migrations/V031__tenant_isolation_probe.sql"
SURFACES = ("database", "cache", "message", "log", "export")
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")


def _time(value: datetime | None = None) -> datetime:
    result = value or datetime.now(timezone.utc)
    if result.tzinfo is None:
        raise ValidationError("probe timestamps must be timezone-aware")
    return result.astimezone(timezone.utc)


def _text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def _identifier(value: str, field: str) -> str:
    require_text(value, field)
    if not IDENTIFIER.fullmatch(value):
        raise ValidationError(f"{field} has an invalid format")
    return value


def _digest(value: str, field: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{64}", value or ""):
        raise ValidationError(f"{field} must be a lowercase SHA-256 digest")
    return value


@dataclass(frozen=True)
class SurfaceObservation:
    surface: str
    owner_visible: bool
    owner_digest: str | None
    cross_tenant_denied: bool
    response_digest: str
    reason_code: str

    @property
    def passed(self) -> bool:
        return self.owner_visible and self.cross_tenant_denied


class IsolationSurface(Protocol):
    def observe(
        self,
        *,
        owner_tenant_id: str,
        attacker_tenant_id: str,
        canary_id: str,
        expected_digest: str,
        nonce: str,
    ) -> SurfaceObservation: ...


class _ClosingConnection(sqlite3.Connection):
    def __exit__(self, exc_type: object, exc: object, traceback: object) -> bool:
        try:
            return bool(super().__exit__(exc_type, exc, traceback))
        finally:
            self.close()


class HttpIsolationSurface:
    """Reads an already-provisioned canary through a deployment-owned probe gateway."""

    def __init__(
        self,
        surface: str,
        endpoint: str,
        ssl_context: ssl.SSLContext,
        access_token: str,
        *,
        timeout_seconds: int = 5,
        maximum_response_bytes: int = 65_536,
    ) -> None:
        if surface not in SURFACES:
            raise ValidationError("unknown isolation surface")
        parsed = urlsplit(endpoint)
        if (parsed.scheme.lower() != "https" or not parsed.hostname or parsed.username
                or parsed.password or parsed.query or parsed.fragment
                or parsed.port not in (None, 443)):
            raise ValidationError("isolation probe endpoint must be HTTPS on port 443")
        if not parsed.path.endswith("/isolation-probe/read"):
            raise ValidationError("isolation probe endpoint path is not approved")
        require_text(access_token, "access_token")
        if "\r" in access_token or "\n" in access_token or len(access_token) > 8_192:
            raise ValidationError("access token has an invalid format")
        if isinstance(timeout_seconds, bool) or not 1 <= timeout_seconds <= 30:
            raise ValidationError("timeout_seconds must be 1..30")
        if not 1_024 <= maximum_response_bytes <= 1_048_576:
            raise ValidationError("maximum_response_bytes is outside its safe bound")
        self.surface = surface
        self.host = parsed.hostname
        self.path = parsed.path
        self.context = ssl_context
        self.token = access_token
        self.timeout = timeout_seconds
        self.maximum = maximum_response_bytes

    def observe(
        self,
        *,
        owner_tenant_id: str,
        attacker_tenant_id: str,
        canary_id: str,
        expected_digest: str,
        nonce: str,
    ) -> SurfaceObservation:
        request = {
            "surface": self.surface,
            "ownerTenantId": owner_tenant_id,
            "attackerTenantId": attacker_tenant_id,
            "canaryId": canary_id,
            "expectedDigest": expected_digest,
            "nonce": nonce,
            "operation": "READ_ONLY_CROSS_TENANT_CANARY",
        }
        body = canonical_json(request)
        connection = http.client.HTTPSConnection(
            self.host, 443, timeout=self.timeout, context=self.context,
        )
        try:
            connection.request("POST", self.path, body=body, headers={
                "Authorization": "Bearer " + self.token,
                "Content-Type": "application/json",
                "Accept": "application/json",
                "X-Elmpay-Probe-Nonce": nonce,
            })
            response = connection.getresponse()
            raw = response.read(self.maximum + 1)
        except (OSError, http.client.HTTPException, ssl.SSLError) as exception:
            raise ValidationError("isolation surface is unavailable") from exception
        finally:
            connection.close()
        if response.status != 200 or len(raw) == 0 or len(raw) > self.maximum:
            raise ValidationError("isolation surface returned an unsafe response")
        try:
            document = require_mapping(json.loads(raw), "isolation response")
        except (UnicodeDecodeError, json.JSONDecodeError) as exception:
            raise ValidationError("isolation surface response is malformed") from exception
        if document.get("surface") != self.surface or document.get("nonce") != nonce:
            raise ValidationError("isolation response binding mismatch")
        owner = require_mapping(document.get("ownerRead"), "ownerRead")
        cross = require_mapping(document.get("crossTenantRead"), "crossTenantRead")
        owner_visible = owner.get("found") is True and owner.get("digest") == expected_digest
        cross_denied = cross.get("denied") is True and cross.get("found") is not True
        reason = "ISOLATED" if owner_visible and cross_denied else "CROSS_TENANT_LEAK_OR_CANARY_MISSING"
        return SurfaceObservation(
            self.surface, owner_visible, owner.get("digest") if isinstance(owner.get("digest"), str)
            else None, cross_denied, sha256_json(document), reason,
        )


class TenantIsolationProbeRunner:
    def __init__(
        self,
        database: str | Path,
        surfaces: Mapping[str, IsolationSurface],
    ) -> None:
        self.database = str(database)
        if self.database == ":memory:":
            raise ValidationError("isolation probe results require a filesystem database")
        if set(surfaces) != set(SURFACES):
            raise ValidationError("all five isolation surfaces are required")
        self.surfaces = dict(surfaces)
        path = Path(self.database)
        path.parent.mkdir(parents=True, exist_ok=True)
        if not MIGRATION.is_file():
            raise ValidationError("B31 database migration is missing")
        with self._connect() as connection:
            connection.executescript(MIGRATION.read_text(encoding="utf-8"))

    def run(
        self,
        *,
        owner_tenant_id: str,
        attacker_tenant_id: str,
        canary_id: str,
        expected_digest: str,
        run_id: str | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        owner_tenant_id = _identifier(owner_tenant_id, "owner_tenant_id")
        attacker_tenant_id = _identifier(attacker_tenant_id, "attacker_tenant_id")
        canary_id = _identifier(canary_id, "canary_id")
        _digest(expected_digest, "expected_digest")
        if owner_tenant_id == attacker_tenant_id:
            raise ValidationError("probe tenants must be different")
        request = {
            "ownerTenantId": owner_tenant_id,
            "attackerTenantId": attacker_tenant_id,
            "canaryId": canary_id,
            "expectedDigest": expected_digest,
            "surfaces": list(SURFACES),
        }
        request_digest = sha256_json(request)
        run_id = _identifier(run_id, "run_id") if run_id else str(
            uuid.uuid5(uuid.NAMESPACE_URL, "elmpay:isolation:" + request_digest)
        )
        at = _time(now)
        with self._connect() as connection:
            existing = connection.execute(
                "SELECT request_digest,status,result_digest,finished_at FROM "
                "tenant_isolation_probe_run WHERE run_id=?",
                (run_id,),
            ).fetchone()
            if existing:
                if existing["request_digest"] != request_digest:
                    raise ValidationError("probe run id is bound to another request")
                if existing["status"] == "RUNNING":
                    raise ValidationError("probe run is already in progress")
                return self._result(connection, run_id, replayed=True)
            connection.execute(
                "INSERT INTO tenant_isolation_probe_run "
                "(run_id,request_digest,owner_tenant_id,attacker_tenant_id,canary_id,"
                "expected_digest,status,started_at) VALUES(?,?,?,?,?,?,'RUNNING',?)",
                (
                    run_id, request_digest, owner_tenant_id, attacker_tenant_id,
                    canary_id, expected_digest, _text(at),
                ),
            )
        observations: list[SurfaceObservation] = []
        for surface in SURFACES:
            nonce = str(uuid.uuid5(uuid.NAMESPACE_URL, f"{run_id}:{surface}"))
            try:
                observation = self.surfaces[surface].observe(
                    owner_tenant_id=owner_tenant_id,
                    attacker_tenant_id=attacker_tenant_id,
                    canary_id=canary_id,
                    expected_digest=expected_digest,
                    nonce=nonce,
                )
                if observation.surface != surface:
                    raise ValidationError("surface response has the wrong identity")
                if observation.owner_digest != expected_digest:
                    observation = SurfaceObservation(
                        surface, False, observation.owner_digest,
                        observation.cross_tenant_denied, observation.response_digest,
                        "OWNER_CANARY_DIGEST_MISMATCH",
                    )
            except Exception:  # A failed adapter is a failed isolation probe, never a skip.
                observation = SurfaceObservation(
                    surface, False, None, False, sha256_json({
                        "runId": run_id, "surface": surface, "outcome": "UNAVAILABLE",
                    }), "SURFACE_UNAVAILABLE",
                )
            observations.append(observation)
        summary = [{
            "surface": item.surface,
            "status": "PASSED" if item.passed else "FAILED",
            "ownerVisible": item.owner_visible,
            "crossTenantDenied": item.cross_tenant_denied,
            "responseDigest": item.response_digest,
            "reasonCode": item.reason_code,
        } for item in observations]
        status = "PASSED" if all(item.passed for item in observations) else "FAILED"
        result_digest = sha256_json(summary)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            for item in observations:
                connection.execute(
                    "INSERT INTO tenant_isolation_probe_result VALUES(?,?,?,?,?,?,?,?)",
                    (
                        run_id, item.surface, "PASSED" if item.passed else "FAILED",
                        int(item.owner_visible), int(item.cross_tenant_denied),
                        item.response_digest, item.reason_code, _text(at),
                    ),
                )
            changed = connection.execute(
                "UPDATE tenant_isolation_probe_run SET status=?,finished_at=?,result_digest=? "
                "WHERE run_id=? AND status='RUNNING'",
                (status, _text(at), result_digest, run_id),
            ).rowcount
            if changed != 1:
                connection.rollback()
                raise ValidationError("probe run completion was concurrently fenced")
            connection.commit()
            return self._result(connection, run_id, replayed=False)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database, timeout=10, factory=_ClosingConnection)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=10000")
        connection.execute("PRAGMA journal_mode=WAL")
        return connection

    @staticmethod
    def _result(connection: sqlite3.Connection, run_id: str, *, replayed: bool) -> dict[str, Any]:
        run = connection.execute(
            "SELECT status,result_digest FROM tenant_isolation_probe_run WHERE run_id=?",
            (run_id,),
        ).fetchone()
        rows = connection.execute(
            "SELECT surface,status,owner_visible,cross_tenant_denied,response_digest,reason_code "
            "FROM tenant_isolation_probe_result WHERE run_id=? ORDER BY surface",
            (run_id,),
        ).fetchall()
        return {
            "runId": run_id,
            "status": run["status"],
            "resultDigest": run["result_digest"],
            "surfaces": [{
                "surface": row["surface"],
                "status": row["status"],
                "ownerVisible": bool(row["owner_visible"]),
                "crossTenantDenied": bool(row["cross_tenant_denied"]),
                "responseDigest": row["response_digest"],
                "reasonCode": row["reason_code"],
            } for row in rows],
            "replayed": replayed,
            "certificationStatus": "NOT_CERTIFIED",
        }
