"""Durable B15 legacy-to-platform migration control plane.

Provider calls happen outside this component exactly once.  The immutable provider result is
then journaled atomically with one or two idempotent projection deliveries according to the
project phase.  Delivery workers use expiring leases and fencing tokens, so a crashed worker can
be replaced without allowing a stale acknowledgement to drop a write.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re
import sqlite3
from typing import Any, Iterator, Mapping, Sequence
import uuid

from .common import ValidationError, canonical_json, require_mapping, require_text, sha256_json


MIGRATION = Path(__file__).resolve().parents[1] / "migrations/V015__service_migration.sql"
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
PHASES = (
    "LEGACY_ONLY",
    "DUAL_WRITE_LEGACY_AUTHORITATIVE",
    "DUAL_WRITE_PLATFORM_AUTHORITATIVE",
    "PLATFORM_ONLY",
    "ROLLED_BACK",
)
TRANSITIONS = {
    "LEGACY_ONLY": {"DUAL_WRITE_LEGACY_AUTHORITATIVE"},
    "DUAL_WRITE_LEGACY_AUTHORITATIVE": {"DUAL_WRITE_PLATFORM_AUTHORITATIVE", "ROLLED_BACK"},
    "DUAL_WRITE_PLATFORM_AUTHORITATIVE": {"PLATFORM_ONLY", "ROLLED_BACK"},
    "PLATFORM_ONLY": {"ROLLED_BACK"},
    "ROLLED_BACK": {"LEGACY_ONLY"},
}


def _instant(value: datetime | None = None) -> datetime:
    result = value or datetime.now(timezone.utc)
    if result.tzinfo is None:
        raise ValidationError("timestamps must be timezone-aware")
    return result.astimezone(timezone.utc)


def _text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def _id(value: str, field: str) -> str:
    require_text(value, field)
    if not IDENTIFIER.fullmatch(value):
        raise ValidationError(f"{field} has an invalid format")
    return value


def _digest(value: str, field: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{64}", value or ""):
        raise ValidationError(f"{field} must be a lowercase SHA-256 digest")
    return value


class _Connection(sqlite3.Connection):
    def __exit__(self, exc_type: object, exc: object, traceback: object) -> bool:
        try:
            return bool(super().__exit__(exc_type, exc, traceback))
        finally:
            self.close()


@dataclass(frozen=True)
class DeliveryLease:
    tenant_id: str
    project_id: str
    operation_id: str
    target: str
    payload: Mapping[str, Any]
    payload_digest: str
    lease_owner: str
    lease_token: int
    lease_expires_at: str


class ServiceMigrationControl:
    """SQLite-backed operational control plane suitable for one active project worker set."""

    def __init__(self, database: str | Path) -> None:
        self.database = str(database)
        if self.database == ":memory:":
            raise ValidationError("service migration requires a filesystem-backed database")
        path = Path(self.database)
        path.parent.mkdir(parents=True, exist_ok=True)
        if not MIGRATION.is_file():
            raise ValidationError("B15 database migration is missing")
        with self._connect() as connection:
            connection.executescript(MIGRATION.read_text(encoding="utf-8"))

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.database,
            timeout=10,
            isolation_level=None,
            factory=_Connection,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=10000")
        connection.execute("PRAGMA journal_mode=WAL")
        return connection

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def register_project(
        self,
        tenant_id: str,
        project_id: str,
        configuration: Mapping[str, Any],
        *,
        now: datetime | None = None,
    ) -> str:
        tenant_id, project_id = _id(tenant_id, "tenant_id"), _id(project_id, "project_id")
        digest = sha256_json(require_mapping(configuration, "configuration"))
        at = _text(_instant(now))
        with self._transaction() as connection:
            existing = connection.execute(
                "SELECT configuration_digest FROM service_migration_project "
                "WHERE tenant_id=? AND project_id=?",
                (tenant_id, project_id),
            ).fetchone()
            if existing and existing["configuration_digest"] != digest:
                raise ValidationError("migration project configuration is immutable")
            if not existing:
                connection.execute(
                    "INSERT INTO service_migration_project VALUES(?,?,?,?,?,?)",
                    (tenant_id, project_id, "LEGACY_ONLY", 1, digest, at),
                )
                self._audit(connection, tenant_id, project_id, "REGISTER", digest, at)
        return digest

    def record_provider_result(
        self,
        *,
        tenant_id: str,
        project_id: str,
        operation_id: str,
        idempotency_key: str,
        request: Mapping[str, Any],
        provider_reference: str,
        provider_result: Mapping[str, Any],
        legacy_projection: Mapping[str, Any],
        platform_projection: Mapping[str, Any],
        now: datetime | None = None,
    ) -> dict[str, Any]:
        tenant_id, project_id = _id(tenant_id, "tenant_id"), _id(project_id, "project_id")
        operation_id = _id(operation_id, "operation_id")
        idempotency_key = _id(idempotency_key, "idempotency_key")
        provider_reference = _id(provider_reference, "provider_reference")
        request_digest = sha256_json(require_mapping(request, "request"))
        result_digest = sha256_json(require_mapping(provider_result, "provider_result"))
        projections = {
            "legacy": require_mapping(legacy_projection, "legacy_projection"),
            "platform": require_mapping(platform_projection, "platform_projection"),
        }
        at = _text(_instant(now))
        with self._transaction() as connection:
            project = self._project(connection, tenant_id, project_id)
            targets, authority = self._targets(project["phase"])
            existing = connection.execute(
                "SELECT operation_id,request_digest,provider_reference,provider_result_digest,authority "
                "FROM service_migration_write_journal WHERE tenant_id=? AND project_id=? "
                "AND idempotency_key=?",
                (tenant_id, project_id, idempotency_key),
            ).fetchone()
            intended = (operation_id, request_digest, provider_reference, result_digest, authority)
            if existing:
                observed = tuple(existing[key] for key in (
                    "operation_id", "request_digest", "provider_reference",
                    "provider_result_digest", "authority",
                ))
                if observed != intended:
                    raise ValidationError("idempotency key is bound to a different provider result")
                return self._journal(connection, tenant_id, project_id, operation_id, replayed=True)
            collision = connection.execute(
                "SELECT idempotency_key FROM service_migration_write_journal "
                "WHERE tenant_id=? AND project_id=? AND operation_id=?",
                (tenant_id, project_id, operation_id),
            ).fetchone()
            if collision:
                raise ValidationError("operation_id is already bound to another request")
            connection.execute(
                "INSERT INTO service_migration_write_journal VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    tenant_id, project_id, operation_id, idempotency_key, request_digest,
                    provider_reference, result_digest, authority, "PENDING", at,
                ),
            )
            for target in targets:
                payload = projections[target]
                encoded = canonical_json(payload).decode("utf-8")
                connection.execute(
                    "INSERT INTO service_migration_projection_delivery "
                    "(tenant_id,project_id,operation_id,target,payload_json,payload_digest,state,"
                    "attempt_count,next_attempt_at,lease_token) VALUES(?,?,?,?,?,?,'PENDING',0,?,0)",
                    (tenant_id, project_id, operation_id, target, encoded, sha256_json(payload), at),
                )
            self._audit(connection, tenant_id, project_id, "PROVIDER_RESULT", result_digest, at)
            return self._journal(connection, tenant_id, project_id, operation_id, replayed=False)

    def claim_delivery(
        self,
        tenant_id: str,
        project_id: str,
        target: str,
        worker_id: str,
        *,
        now: datetime | None = None,
        lease_seconds: int = 30,
    ) -> DeliveryLease | None:
        tenant_id, project_id = _id(tenant_id, "tenant_id"), _id(project_id, "project_id")
        worker_id = _id(worker_id, "worker_id")
        if target not in {"legacy", "platform"}:
            raise ValidationError("target must be legacy or platform")
        if isinstance(lease_seconds, bool) or not 1 <= lease_seconds <= 300:
            raise ValidationError("lease_seconds must be 1..300")
        current = _instant(now)
        expires = current + timedelta(seconds=lease_seconds)
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT operation_id,payload_json,payload_digest,lease_token "
                "FROM service_migration_projection_delivery WHERE tenant_id=? AND project_id=? "
                "AND target=? AND ((state='PENDING' AND next_attempt_at<=?) OR "
                "(state='IN_FLIGHT' AND lease_expires_at<=?)) "
                "ORDER BY next_attempt_at, operation_id LIMIT 1",
                (tenant_id, project_id, target, _text(current), _text(current)),
            ).fetchone()
            if row is None:
                return None
            token = int(row["lease_token"]) + 1
            changed = connection.execute(
                "UPDATE service_migration_projection_delivery SET state='IN_FLIGHT',"
                "lease_owner=?,lease_token=?,lease_expires_at=?,attempt_count=attempt_count+1 "
                "WHERE tenant_id=? AND project_id=? AND operation_id=? AND target=? "
                "AND lease_token=?",
                (
                    worker_id, token, _text(expires), tenant_id, project_id,
                    row["operation_id"], target, row["lease_token"],
                ),
            ).rowcount
            if changed != 1:
                raise ValidationError("delivery lease was concurrently claimed")
            return DeliveryLease(
                tenant_id, project_id, row["operation_id"], target,
                json.loads(row["payload_json"]), row["payload_digest"],
                worker_id, token, _text(expires),
            )

    def acknowledge_delivery(
        self,
        lease: DeliveryLease,
        remote_digest: str,
        *,
        now: datetime | None = None,
    ) -> None:
        _digest(remote_digest, "remote_digest")
        if remote_digest != lease.payload_digest:
            raise ValidationError("remote projection digest does not match the leased payload")
        at = _text(_instant(now))
        with self._transaction() as connection:
            changed = connection.execute(
                "UPDATE service_migration_projection_delivery SET state='ACKED',acknowledged_at=?,"
                "lease_owner=NULL,lease_expires_at=NULL,last_error=NULL WHERE tenant_id=? AND "
                "project_id=? AND operation_id=? AND target=? AND state='IN_FLIGHT' "
                "AND lease_owner=? AND lease_token=?",
                (
                    at, lease.tenant_id, lease.project_id, lease.operation_id, lease.target,
                    lease.lease_owner, lease.lease_token,
                ),
            ).rowcount
            if changed != 1:
                raise ValidationError("stale delivery acknowledgement was fenced")
            self._refresh_divergence(connection, lease.tenant_id, lease.project_id,
                                     lease.operation_id)

    def retry_delivery(
        self,
        lease: DeliveryLease,
        error_code: str,
        *,
        now: datetime | None = None,
        delay_seconds: int = 5,
    ) -> None:
        error_code = _id(error_code, "error_code")
        if isinstance(delay_seconds, bool) or not 1 <= delay_seconds <= 3600:
            raise ValidationError("delay_seconds must be 1..3600")
        next_attempt = _instant(now) + timedelta(seconds=delay_seconds)
        with self._transaction() as connection:
            changed = connection.execute(
                "UPDATE service_migration_projection_delivery SET state='PENDING',next_attempt_at=?,"
                "lease_owner=NULL,lease_expires_at=NULL,last_error=? WHERE tenant_id=? AND project_id=? "
                "AND operation_id=? AND target=? AND state='IN_FLIGHT' AND lease_owner=? "
                "AND lease_token=?",
                (
                    _text(next_attempt), error_code, lease.tenant_id, lease.project_id,
                    lease.operation_id, lease.target, lease.lease_owner, lease.lease_token,
                ),
            ).rowcount
            if changed != 1:
                raise ValidationError("stale delivery retry was fenced")

    def import_backfill_page(
        self,
        tenant_id: str,
        project_id: str,
        source_stream: str,
        records: Sequence[Mapping[str, Any]],
        *,
        now: datetime | None = None,
    ) -> dict[str, int]:
        tenant_id, project_id = _id(tenant_id, "tenant_id"), _id(project_id, "project_id")
        source_stream = _id(source_stream, "source_stream")
        if not records:
            raise ValidationError("backfill page must not be empty")
        normalized: list[tuple[int, str, Mapping[str, Any], int, str]] = []
        for item in records:
            record = require_mapping(item, "backfill record")
            position = record.get("sourcePosition")
            amount = record.get("amountMinor")
            record_id = _id(str(record.get("sourceRecordId", "")), "sourceRecordId")
            if isinstance(position, bool) or not isinstance(position, int) or position < 0:
                raise ValidationError("sourcePosition must be a non-negative integer")
            if isinstance(amount, bool) or not isinstance(amount, int):
                raise ValidationError("amountMinor must be an integer")
            normalized.append((position, record_id, record, amount, sha256_json(record)))
        normalized.sort(key=lambda item: item[0])
        if len({item[0] for item in normalized}) != len(normalized):
            raise ValidationError("backfill page contains duplicate sourcePosition")
        at = _text(_instant(now))
        page_digest = sha256_json([item[4] for item in normalized])
        with self._transaction() as connection:
            self._project(connection, tenant_id, project_id)
            checkpoint = connection.execute(
                "SELECT last_position,record_count,amount_minor_sum,last_page_digest "
                "FROM service_migration_backfill_checkpoint WHERE tenant_id=? AND project_id=? "
                "AND source_stream=?",
                (tenant_id, project_id, source_stream),
            ).fetchone()
            last_position = int(checkpoint["last_position"]) if checkpoint else -1
            expected_first = last_position + 1
            if normalized[0][0] < expected_first:
                existing = connection.execute(
                    "SELECT canonical_digest FROM service_migration_backfill_record "
                    "WHERE tenant_id=? AND project_id=? AND source_position>=? "
                    "ORDER BY source_position LIMIT ?",
                    (tenant_id, project_id, normalized[0][0], len(normalized)),
                ).fetchall()
                if [row["canonical_digest"] for row in existing] == [item[4] for item in normalized]:
                    return {
                        "lastPosition": last_position,
                        "recordCount": int(checkpoint["record_count"]),
                        "amountMinorSum": int(checkpoint["amount_minor_sum"]),
                    }
                raise ValidationError("backfill replay differs from previously imported data")
            if normalized[0][0] != expected_first:
                raise ValidationError("backfill page has a checkpoint gap")
            for left, right in zip(normalized, normalized[1:]):
                if right[0] != left[0] + 1:
                    raise ValidationError("backfill page positions must be contiguous")
            for position, record_id, record, amount, digest in normalized:
                connection.execute(
                    "INSERT INTO service_migration_backfill_record VALUES(?,?,?,?,?,?,?,?)",
                    (
                        tenant_id, project_id, record_id, position,
                        canonical_json(record).decode("utf-8"), digest, amount, at,
                    ),
                )
            previous_count = int(checkpoint["record_count"]) if checkpoint else 0
            previous_sum = int(checkpoint["amount_minor_sum"]) if checkpoint else 0
            result = {
                "lastPosition": normalized[-1][0],
                "recordCount": previous_count + len(normalized),
                "amountMinorSum": previous_sum + sum(item[3] for item in normalized),
            }
            connection.execute(
                "INSERT INTO service_migration_backfill_checkpoint VALUES(?,?,?,?,?,?,?,?) "
                "ON CONFLICT(tenant_id,project_id,source_stream) DO UPDATE SET "
                "last_position=excluded.last_position,record_count=excluded.record_count,"
                "amount_minor_sum=excluded.amount_minor_sum,last_page_digest=excluded.last_page_digest,"
                "updated_at=excluded.updated_at",
                (
                    tenant_id, project_id, source_stream, result["lastPosition"],
                    result["recordCount"], result["amountMinorSum"], page_digest, at,
                ),
            )
            self._audit(connection, tenant_id, project_id, "BACKFILL_PAGE", page_digest, at)
            return result

    def propose_cutover(
        self,
        tenant_id: str,
        project_id: str,
        target_phase: str,
        evidence: Mapping[str, Any],
        proposer: str,
        *,
        now: datetime | None = None,
    ) -> str:
        tenant_id, project_id = _id(tenant_id, "tenant_id"), _id(project_id, "project_id")
        proposer = _id(proposer, "proposer")
        if target_phase not in PHASES:
            raise ValidationError("unknown target phase")
        evidence = require_mapping(evidence, "evidence")
        self._validate_cutover_evidence(evidence)
        at = _text(_instant(now))
        with self._transaction() as connection:
            project = self._project(connection, tenant_id, project_id)
            if target_phase not in TRANSITIONS[project["phase"]]:
                raise ValidationError("illegal migration phase transition")
            if target_phase in {"DUAL_WRITE_PLATFORM_AUTHORITATIVE", "PLATFORM_ONLY"}:
                unsafe = connection.execute(
                    "SELECT COUNT(*) FROM service_migration_write_journal j WHERE "
                    "j.tenant_id=? AND j.project_id=? AND (j.divergence_state<>'MATCHED' OR "
                    "EXISTS (SELECT 1 FROM service_migration_projection_delivery d WHERE "
                    "d.tenant_id=j.tenant_id AND d.project_id=j.project_id "
                    "AND d.operation_id=j.operation_id AND d.state<>'ACKED'))",
                    (tenant_id, project_id),
                ).fetchone()[0]
                dual_written = connection.execute(
                    "SELECT COUNT(*) FROM service_migration_write_journal j WHERE "
                    "j.tenant_id=? AND j.project_id=? AND "
                    "(SELECT COUNT(*) FROM service_migration_projection_delivery d WHERE "
                    "d.tenant_id=j.tenant_id AND d.project_id=j.project_id "
                    "AND d.operation_id=j.operation_id)=2",
                    (tenant_id, project_id),
                ).fetchone()[0]
                if unsafe or not dual_written:
                    raise ValidationError("cutover requires matched, fully acknowledged dual writes")
                checkpoint = connection.execute(
                    "SELECT COALESCE(SUM(record_count),0),COALESCE(SUM(amount_minor_sum),0) "
                    "FROM service_migration_backfill_checkpoint WHERE tenant_id=? AND project_id=?",
                    (tenant_id, project_id),
                ).fetchone()
                if (int(checkpoint[0]), int(checkpoint[1])) != (
                    evidence["platformCount"], evidence["platformAmountMinor"]
                ):
                    raise ValidationError("cutover evidence is not bound to durable backfill totals")
            evidence_digest = sha256_json(evidence)
            cutover_id = str(uuid.uuid5(
                uuid.NAMESPACE_URL,
                f"elmpay:{tenant_id}:{project_id}:{project['phase_version']}:{target_phase}:{evidence_digest}",
            ))
            existing = connection.execute(
                "SELECT proposer,evidence_digest FROM service_migration_cutover "
                "WHERE tenant_id=? AND project_id=? AND cutover_id=?",
                (tenant_id, project_id, cutover_id),
            ).fetchone()
            if existing:
                if (existing["proposer"], existing["evidence_digest"]) != (proposer, evidence_digest):
                    raise ValidationError("cutover proposal collision")
                return cutover_id
            connection.execute(
                "INSERT INTO service_migration_cutover "
                "(tenant_id,project_id,cutover_id,expected_phase,target_phase,"
                "expected_phase_version,evidence_digest,proposer,state,proposed_at) "
                "VALUES(?,?,?,?,?,?,?,?, 'PROPOSED',?)",
                (
                    tenant_id, project_id, cutover_id, project["phase"], target_phase,
                    project["phase_version"], evidence_digest, proposer, at,
                ),
            )
            self._audit(connection, tenant_id, project_id, "CUTOVER_PROPOSE", evidence_digest, at)
            return cutover_id

    def approve_cutover(
        self,
        tenant_id: str,
        project_id: str,
        cutover_id: str,
        approver: str,
        evidence: Mapping[str, Any],
        *,
        now: datetime | None = None,
    ) -> str:
        tenant_id, project_id = _id(tenant_id, "tenant_id"), _id(project_id, "project_id")
        cutover_id, approver = _id(cutover_id, "cutover_id"), _id(approver, "approver")
        evidence = require_mapping(evidence, "evidence")
        self._validate_cutover_evidence(evidence)
        at = _text(_instant(now))
        with self._transaction() as connection:
            proposal = connection.execute(
                "SELECT * FROM service_migration_cutover WHERE tenant_id=? AND project_id=? "
                "AND cutover_id=? AND state='PROPOSED'",
                (tenant_id, project_id, cutover_id),
            ).fetchone()
            if proposal is None:
                raise ValidationError("cutover proposal is not pending")
            if proposal["proposer"] == approver:
                raise ValidationError("cutover requires a distinct approver")
            if proposal["evidence_digest"] != sha256_json(evidence):
                raise ValidationError("cutover evidence changed after proposal")
            changed = connection.execute(
                "UPDATE service_migration_project SET phase=?,phase_version=phase_version+1,updated_at=? "
                "WHERE tenant_id=? AND project_id=? AND phase=? AND phase_version=?",
                (
                    proposal["target_phase"], at, tenant_id, project_id,
                    proposal["expected_phase"], proposal["expected_phase_version"],
                ),
            ).rowcount
            if changed != 1:
                raise ValidationError("cutover proposal was fenced by a newer phase")
            connection.execute(
                "UPDATE service_migration_cutover SET approver=?,state='APPLIED',decided_at=? "
                "WHERE tenant_id=? AND project_id=? AND cutover_id=?",
                (approver, at, tenant_id, project_id, cutover_id),
            )
            self._audit(
                connection, tenant_id, project_id, "CUTOVER_APPLY",
                proposal["evidence_digest"], at,
            )
            return str(proposal["target_phase"])

    @staticmethod
    def _validate_cutover_evidence(evidence: Mapping[str, Any]) -> None:
        required = ("sourceCount", "platformCount", "sourceAmountMinor", "platformAmountMinor",
                    "divergenceCount")
        for field in required:
            value = evidence.get(field)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValidationError(f"cutover evidence {field} must be non-negative integer")
        if evidence["sourceCount"] != evidence["platformCount"]:
            raise ValidationError("cutover count reconciliation failed")
        if evidence["sourceAmountMinor"] != evidence["platformAmountMinor"]:
            raise ValidationError("cutover amount reconciliation failed")
        if evidence["divergenceCount"] != 0:
            raise ValidationError("cutover has unresolved divergences")

    @staticmethod
    def _targets(phase: str) -> tuple[tuple[str, ...], str]:
        if phase == "LEGACY_ONLY" or phase == "ROLLED_BACK":
            return ("legacy",), "legacy"
        if phase == "DUAL_WRITE_LEGACY_AUTHORITATIVE":
            return ("legacy", "platform"), "legacy"
        if phase == "DUAL_WRITE_PLATFORM_AUTHORITATIVE":
            return ("legacy", "platform"), "platform"
        if phase == "PLATFORM_ONLY":
            return ("platform",), "platform"
        raise ValidationError("unknown project phase")

    @staticmethod
    def _project(connection: sqlite3.Connection, tenant_id: str, project_id: str) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM service_migration_project WHERE tenant_id=? AND project_id=?",
            (tenant_id, project_id),
        ).fetchone()
        if row is None:
            raise ValidationError("migration project is not registered")
        return row

    @staticmethod
    def _journal(
        connection: sqlite3.Connection,
        tenant_id: str,
        project_id: str,
        operation_id: str,
        *,
        replayed: bool,
    ) -> dict[str, Any]:
        row = connection.execute(
            "SELECT provider_reference,provider_result_digest,authority,divergence_state "
            "FROM service_migration_write_journal WHERE tenant_id=? AND project_id=? "
            "AND operation_id=?",
            (tenant_id, project_id, operation_id),
        ).fetchone()
        targets = connection.execute(
            "SELECT target FROM service_migration_projection_delivery WHERE tenant_id=? "
            "AND project_id=? AND operation_id=? ORDER BY target",
            (tenant_id, project_id, operation_id),
        ).fetchall()
        return {
            "operationId": operation_id,
            "providerReference": row["provider_reference"],
            "providerResultDigest": row["provider_result_digest"],
            "authority": row["authority"],
            "divergenceState": row["divergence_state"],
            "targets": [target["target"] for target in targets],
            "replayed": replayed,
        }

    @staticmethod
    def _refresh_divergence(
        connection: sqlite3.Connection,
        tenant_id: str,
        project_id: str,
        operation_id: str,
    ) -> None:
        rows = connection.execute(
            "SELECT target,payload_digest,state FROM service_migration_projection_delivery "
            "WHERE tenant_id=? AND project_id=? AND operation_id=? ORDER BY target",
            (tenant_id, project_id, operation_id),
        ).fetchall()
        if not rows or any(row["state"] != "ACKED" for row in rows):
            return
        state = "MATCHED" if len(rows) == 1 or len({row["payload_digest"] for row in rows}) == 1 \
            else "DIVERGED"
        connection.execute(
            "UPDATE service_migration_write_journal SET divergence_state=? WHERE tenant_id=? "
            "AND project_id=? AND operation_id=?",
            (state, tenant_id, project_id, operation_id),
        )

    @staticmethod
    def _audit(
        connection: sqlite3.Connection,
        tenant_id: str,
        project_id: str,
        action: str,
        object_digest: str,
        occurred_at: str,
    ) -> None:
        connection.execute(
            "INSERT INTO service_migration_audit "
            "(tenant_id,project_id,action,object_digest,occurred_at) VALUES(?,?,?,?,?)",
            (tenant_id, project_id, action, object_digest, occurred_at),
        )
