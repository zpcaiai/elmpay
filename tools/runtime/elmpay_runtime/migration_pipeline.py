"""Tenant-scoped durable migration and side-effect-free shadow controls (B120-B121)."""
from __future__ import annotations

from datetime import datetime, timezone
import re
from typing import Any, Mapping

from .common import ValidationError, canonical_json, require_mapping, require_text, sha256_json
from .durable import DurableStore


CREDENTIAL_REF = re.compile(r"^(?:kms|vault|secret)://[A-Za-z0-9._/:-]{3,240}$")
SENSITIVE = re.compile(r"(?:name|email|phone|address|pan|card|cvv|cvc|password|secret|token)", re.I)
PHASES = ("REGISTERED", "IMPORT", "DUAL_WRITE", "SHADOW", "CUTOVER", "COMPLETE")


def _now(value: datetime | None = None) -> str:
    return (value or datetime.now(timezone.utc)).astimezone(timezone.utc).isoformat()


def redact(value: object) -> object:
    if isinstance(value, dict):
        return {
            str(key): "[REDACTED]" if SENSITIVE.search(str(key)) else redact(item)
            for key, item in sorted(value.items())
        }
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


class MigrationPipeline:
    def __init__(self, database: str) -> None:
        self.store = DurableStore(database)

    def register(
        self,
        *,
        tenant_id: str,
        project_id: str,
        source_system: str,
        canonical_version: str,
        mapping: Mapping[str, Any],
        credential_ref: str,
        now: datetime | None = None,
    ) -> str:
        for field, value in (("tenant_id", tenant_id), ("project_id", project_id), ("source_system", source_system), ("canonical_version", canonical_version)):
            require_text(value, field)
        if not CREDENTIAL_REF.fullmatch(credential_ref):
            raise ValidationError("migration credentials must be an indirect kms/vault/secret reference")
        mapping_digest = sha256_json(require_mapping(mapping, "mapping"))
        instant = _now(now)
        with self.store.transaction() as connection:
            row = connection.execute(
                "SELECT source_system,canonical_version,mapping_digest,credential_ref FROM migration_project WHERE tenant_id=? AND project_id=?",
                (tenant_id, project_id),
            ).fetchone()
            intended = (source_system, canonical_version, mapping_digest, credential_ref)
            if row and tuple(row) != intended:
                raise ValidationError("migration project registration is immutable")
            if not row:
                connection.execute(
                    "INSERT INTO migration_project VALUES(?,?,?,?,?,?,?,?)",
                    (tenant_id, project_id, source_system, canonical_version, mapping_digest, credential_ref, "REGISTERED", instant),
                )
                self._audit(connection, tenant_id, project_id, "REGISTER", mapping_digest, instant)
        return mapping_digest

    def transition(self, tenant_id: str, project_id: str, expected_phase: str, next_phase: str, *, now: datetime | None = None) -> None:
        if expected_phase not in PHASES or next_phase not in (*PHASES, "ROLLED_BACK"):
            raise ValidationError("unknown migration phase")
        if next_phase != "ROLLED_BACK" and PHASES.index(next_phase) != PHASES.index(expected_phase) + 1:
            raise ValidationError("migration phases must advance exactly one step")
        if expected_phase == "COMPLETE":
            raise ValidationError("completed migration projects are immutable")
        instant = _now(now)
        with self.store.transaction() as connection:
            changed = connection.execute(
                "UPDATE migration_project SET phase=?,updated_at=? WHERE tenant_id=? AND project_id=? AND phase=?",
                (next_phase, instant, tenant_id, project_id, expected_phase),
            ).rowcount
            if changed != 1:
                raise ValidationError("migration phase compare-and-set failed")
            self._audit(connection, tenant_id, project_id, f"PHASE:{expected_phase}->{next_phase}", sha256_json({"from": expected_phase, "to": next_phase}), instant)

    def checkpoint(self, tenant_id: str, project_id: str, stream: str, position: int, record: Mapping[str, Any], *, now: datetime | None = None) -> bool:
        if isinstance(position, bool) or not isinstance(position, int) or position < 0:
            raise ValidationError("checkpoint position must be non-negative")
        digest = sha256_json(require_mapping(record, "checkpoint record"))
        with self.store.transaction() as connection:
            row = connection.execute(
                "SELECT position,record_digest FROM migration_checkpoint WHERE tenant_id=? AND project_id=? AND stream=?",
                (tenant_id, project_id, stream),
            ).fetchone()
            if row:
                if position < row["position"]:
                    raise ValidationError("checkpoint regression is forbidden")
                if position == row["position"]:
                    if digest != row["record_digest"]:
                        raise ValidationError("checkpoint position reused with different record")
                    return False
                connection.execute(
                    "UPDATE migration_checkpoint SET position=?,record_digest=?,updated_at=? WHERE tenant_id=? AND project_id=? AND stream=?",
                    (position, digest, _now(now), tenant_id, project_id, stream),
                )
            else:
                connection.execute(
                    "INSERT INTO migration_checkpoint VALUES(?,?,?,?,?,?)",
                    (tenant_id, project_id, stream, position, digest, _now(now)),
                )
            self._audit(connection, tenant_id, project_id, f"CHECKPOINT:{stream}:{position}", digest, _now(now))
        return True

    def ingest_fact(self, tenant_id: str, project_id: str, source_record_id: str, canonical_version: str, fact: Mapping[str, Any], *, now: datetime | None = None) -> bool:
        canonical = require_mapping(fact, "canonical fact")
        safe = require_mapping(redact(canonical), "redacted canonical fact")
        digest = sha256_json(canonical)
        with self.store.transaction() as connection:
            project = connection.execute(
                "SELECT canonical_version FROM migration_project WHERE tenant_id=? AND project_id=?",
                (tenant_id, project_id),
            ).fetchone()
            if not project or project["canonical_version"] != canonical_version:
                raise ValidationError("canonical version does not match migration project")
            row = connection.execute(
                "SELECT canonical_version,fact_digest FROM migration_fact WHERE tenant_id=? AND project_id=? AND source_record_id=?",
                (tenant_id, project_id, source_record_id),
            ).fetchone()
            if row:
                if (row["canonical_version"], row["fact_digest"]) != (canonical_version, digest):
                    raise ValidationError("source record id reused with different canonical fact")
                return False
            connection.execute(
                "INSERT INTO migration_fact VALUES(?,?,?,?,?,?,?)",
                (tenant_id, project_id, source_record_id, canonical_version, digest, canonical_json(safe).decode(), _now(now)),
            )
            self._audit(connection, tenant_id, project_id, f"FACT:{source_record_id}", digest, _now(now))
        return True

    def accept_webhook(self, tenant_id: str, project_id: str, delivery_id: str, payload: Mapping[str, Any], *, now: datetime | None = None) -> bool:
        digest = sha256_json(require_mapping(payload, "webhook payload"))
        with self.store.transaction() as connection:
            row = connection.execute(
                "SELECT payload_digest FROM migration_webhook_inbox WHERE tenant_id=? AND project_id=? AND delivery_id=?",
                (tenant_id, project_id, delivery_id),
            ).fetchone()
            if row:
                if row["payload_digest"] != digest:
                    raise ValidationError("webhook delivery id reused with different payload")
                return False
            connection.execute("INSERT INTO migration_webhook_inbox VALUES(?,?,?,?,?)", (tenant_id, project_id, delivery_id, digest, _now(now)))
            self._audit(connection, tenant_id, project_id, f"WEBHOOK:{delivery_id}", digest, _now(now))
        return True

    def shadow(
        self,
        tenant_id: str,
        project_id: str,
        run_id: str,
        canonical_version: str,
        baseline: list[Mapping[str, Any]],
        candidate: list[Mapping[str, Any]],
        *,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        dataset_digest = sha256_json(baseline)
        by_id = {require_text(item.get("requestId"), "baseline.requestId"): item for item in baseline}
        candidates = {require_text(item.get("requestId"), "candidate.requestId"): item for item in candidate}
        if len(by_id) != len(baseline) or len(candidates) != len(candidate):
            raise ValidationError("shadow inputs contain duplicate requestId")
        instant = _now(now)
        with self.store.transaction() as connection:
            project = connection.execute("SELECT canonical_version FROM migration_project WHERE tenant_id=? AND project_id=?", (tenant_id, project_id)).fetchone()
            if not project or project["canonical_version"] != canonical_version:
                raise ValidationError("shadow canonical version mismatch")
            prior = connection.execute("SELECT dataset_digest,result_digest,status FROM shadow_run WHERE tenant_id=? AND project_id=? AND run_id=?", (tenant_id, project_id, run_id)).fetchone()
            if prior:
                if prior["dataset_digest"] != dataset_digest:
                    raise ValidationError("immutable shadow run id collision")
                return {"runId": run_id, "datasetDigest": prior["dataset_digest"], "resultDigest": prior["result_digest"], "status": prior["status"]}
            connection.execute("INSERT INTO shadow_run(tenant_id,project_id,run_id,canonical_version,dataset_digest,status,created_at) VALUES(?,?,?,?,?,?,?)", (tenant_id, project_id, run_id, canonical_version, dataset_digest, "RUNNING", instant))
            summaries: list[dict[str, Any]] = []
            for request_id in sorted(set(by_id) | set(candidates)):
                base = by_id.get(request_id, {})
                cand = candidates.get(request_id, {})
                side_effects = cand.get("sideEffects", [])
                if not isinstance(side_effects, list):
                    raise ValidationError("candidate sideEffects must be an array")
                safe_base = redact({k: v for k, v in base.items() if k != "sideEffects"})
                safe_cand = redact({k: v for k, v in cand.items() if k != "sideEffects"})
                matched = safe_base == safe_cand and not side_effects
                diff = {"requestId": request_id, "matched": matched, "candidateSideEffects": len(side_effects)}
                row = {"requestId": request_id, "baselineDigest": sha256_json(safe_base), "candidateDigest": sha256_json(safe_cand), "diffDigest": sha256_json(diff), "matched": matched, "candidateSideEffects": len(side_effects)}
                connection.execute("INSERT INTO shadow_result VALUES(?,?,?,?,?,?,?,?,?)", (tenant_id, project_id, run_id, request_id, row["baselineDigest"], row["candidateDigest"], row["diffDigest"], int(matched), canonical_json(diff).decode()))
                summaries.append(row)
            mismatches = sum(not row["matched"] for row in summaries)
            result_digest = sha256_json(summaries)
            status = "PASSED" if mismatches == 0 and len(by_id) == len(candidates) else "FAILED"
            connection.execute("UPDATE shadow_run SET result_digest=?,sample_count=?,mismatch_count=?,status=?,finished_at=? WHERE tenant_id=? AND project_id=? AND run_id=?", (result_digest, len(summaries), mismatches, status, instant, tenant_id, project_id, run_id))
        return {"runId": run_id, "canonicalVersion": canonical_version, "datasetDigest": dataset_digest, "resultDigest": result_digest, "sampleCount": len(summaries), "mismatchCount": mismatches, "candidateSideEffects": sum(int(row["candidateSideEffects"]) for row in summaries), "status": status, "certificationStatus": "NOT_CERTIFIED"}

    @staticmethod
    def _audit(connection: Any, tenant_id: str, project_id: str, action: str, object_digest: str, occurred_at: str) -> None:
        audit_digest = sha256_json({"tenantId": tenant_id, "projectId": project_id, "action": action, "objectDigest": object_digest, "occurredAt": occurred_at})
        connection.execute("INSERT INTO migration_audit(tenant_id,project_id,action,object_digest,occurred_at,audit_digest) VALUES(?,?,?,?,?,?)", (tenant_id, project_id, action, object_digest, occurred_at, audit_digest))
