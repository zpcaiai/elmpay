"""Tenant-scoped durable migration and side-effect-free shadow controls (B120-B121)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import re
import time
from typing import Any, Mapping, Protocol

from .common import ValidationError, canonical_json, require_mapping, require_text, sha256_json
from .downstream_receipt import verify_downstream_receipt
from .durable import DurableStore


CREDENTIAL_REF = re.compile(r"^(?:kms|vault|secret)://[A-Za-z0-9._/:-]{3,240}$")
SENSITIVE = re.compile(r"(?:name|email|phone|address|pan|card|cvv|cvc|password|secret|token)", re.I)
PHASES = ("REGISTERED", "IMPORT", "DUAL_WRITE", "SHADOW", "CUTOVER", "COMPLETE")
CANONICAL_ORDER_FIELDS = {
    "requestId", "paymentIntentId", "amountMinor", "currency", "action",
    "merchantReference", "providerAccountId", "paymentMethodReference",
}


class MigrationExecutionPort(Protocol):
    """Project-specific adapter port; implementations never receive raw credentials."""

    def submit(self, request: Mapping[str, Any]) -> Mapping[str, Any]: ...

    def rollback(self, request: Mapping[str, Any]) -> Mapping[str, Any]: ...


def _current(value: datetime | None = None) -> datetime:
    current = value or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise ValidationError("migration control time must be timezone-aware")
    return current.astimezone(timezone.utc)


def _now(value: datetime | None = None) -> str:
    return _current(value).isoformat()


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
    def __init__(self, database: str, *, webhook_trust: Mapping[str, Any] | None = None,
                 execution_trust: Mapping[str, Any] | None = None) -> None:
        self.store = DurableStore(database)
        self.webhook_trust = webhook_trust
        self.execution_trust = execution_trust

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
            submit_prefix = f"{project_id}:"
            unresolved = connection.execute(
                "SELECT 1 FROM external_control_operation WHERE tenant_id=? "
                "AND status IN ('IN_FLIGHT','UNKNOWN') AND ("
                "(operation_type='MIGRATION_ROLLBACK' AND operation_id=?) OR "
                "(operation_type='MIGRATION_SUBMIT' "
                "AND substr(operation_id,1,length(?))=?)) LIMIT 1",
                (tenant_id, project_id, submit_prefix, submit_prefix),
            ).fetchone()
            if unresolved:
                raise ValidationError(
                    "migration phase cannot change while an external outcome is unresolved"
                )
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

    def accept_webhook(
        self, tenant_id: str, project_id: str, delivery_id: str,
        payload: Mapping[str, Any], verification_receipt: Mapping[str, Any],
        *, now: datetime | None = None,
    ) -> bool:
        digest = sha256_json(require_mapping(payload, "webhook payload"))
        instant = _current(now)
        with self.store.connect() as connection:
            project = connection.execute(
                "SELECT source_system FROM migration_project WHERE tenant_id=? AND project_id=?",
                (tenant_id, project_id),
            ).fetchone()
        if project is None:
            raise ValidationError("migration webhook project is unknown")
        if self.webhook_trust is None:
            raise ValidationError("migration webhook verifier trust is not configured")
        receipt_digest, _signer = verify_downstream_receipt(
            verification_receipt, self.webhook_trust,
            receipt_type="MIGRATION_WEBHOOK_VERIFICATION", outcome="VERIFIED",
            fields={
                "tenantId": tenant_id, "projectId": project_id,
                "sourceSystem": str(project["source_system"]), "deliveryId": delivery_id,
                "payloadDigest": digest,
            }, required_role="migration_webhook_verifier", now=instant,
        )
        with self.store.transaction() as connection:
            row = connection.execute(
                "SELECT payload_digest FROM migration_webhook_inbox WHERE tenant_id=? AND project_id=? AND delivery_id=?",
                (tenant_id, project_id, delivery_id),
            ).fetchone()
            if row:
                if row["payload_digest"] != digest:
                    raise ValidationError("webhook delivery id reused with different payload")
                return False
            connection.execute("INSERT INTO migration_webhook_inbox VALUES(?,?,?,?,?)", (tenant_id, project_id, delivery_id, digest, _now(instant)))
            self._audit(connection, tenant_id, project_id, f"WEBHOOK:{delivery_id}", receipt_digest, _now(instant))
        return True

    def migrate_order(
        self, tenant_id: str, project_id: str, source_record_id: str,
        source_order: Mapping[str, Any], mapping: Mapping[str, Any],
        signature_receipt: Mapping[str, Any], port: MigrationExecutionPort,
        *, now: datetime | None = None,
    ) -> Mapping[str, Any]:
        """Map, externally sign and idempotently submit one legacy order."""

        instant = _current(now)
        canonical = self._map_order(source_order, mapping)
        canonical_digest = sha256_json(canonical)
        with self.store.connect() as connection:
            project = connection.execute(
                "SELECT source_system,canonical_version,mapping_digest,credential_ref,phase "
                "FROM migration_project WHERE tenant_id=? AND project_id=?",
                (tenant_id, project_id),
            ).fetchone()
            prior = connection.execute(
                "SELECT canonical_version,fact_digest FROM migration_fact "
                "WHERE tenant_id=? AND project_id=? AND source_record_id=?",
                (tenant_id, project_id, source_record_id),
            ).fetchone()
        if project is None or project["phase"] not in {"IMPORT", "DUAL_WRITE", "CUTOVER"}:
            raise ValidationError("migration project is not in an executable phase")
        if project["mapping_digest"] != sha256_json(require_mapping(mapping, "mapping")):
            raise ValidationError("migration mapping does not match the immutable project")
        if prior is not None:
            if prior["fact_digest"] != canonical_digest:
                raise ValidationError("source record id reused with different mapped order")
            return {
                "accepted": True, "duplicate": True, "sourceRecordId": source_record_id,
                "canonicalDigest": canonical_digest,
            }
        idempotency_key = sha256_json({
            "tenantId": tenant_id, "projectId": project_id,
            "sourceRecordId": source_record_id, "canonicalDigest": canonical_digest,
        })
        if self.execution_trust is None:
            raise ValidationError("migration execution signer trust is not configured")
        signature_digest, _signer = verify_downstream_receipt(
            signature_receipt, self.execution_trust,
            receipt_type="MIGRATION_REQUEST_SIGNATURE", outcome="SIGNED",
            fields={
                "tenantId": tenant_id, "projectId": project_id,
                "sourceSystem": str(project["source_system"]),
                "sourceRecordId": source_record_id, "canonicalDigest": canonical_digest,
                "idempotencyKey": idempotency_key,
                "credentialRef": str(project["credential_ref"]),
            }, required_role="migration_request_signer", now=instant,
        )
        request = {
            "tenantId": tenant_id, "projectId": project_id,
            "sourceSystem": str(project["source_system"]),
            "sourceRecordId": source_record_id, "canonicalVersion": project["canonical_version"],
            "canonicalOrder": canonical, "canonicalDigest": canonical_digest,
            "idempotencyKey": idempotency_key, "signatureReceiptDigest": signature_digest,
        }
        started_monotonic = time.monotonic()
        reconcile_port = getattr(port, "reconcile_order", None)
        fence_token, lease_owner, request_digest, mode = self._claim_external_operation(
            tenant_id=tenant_id,
            operation_type="MIGRATION_SUBMIT",
            operation_id=f"{project_id}:{source_record_id}",
            binding_digest=canonical_digest,
            request=request,
            allow_reconcile=callable(reconcile_port),
            project_id=project_id,
            project_guard={
                key: project[key] for key in (
                    "source_system", "canonical_version", "mapping_digest",
                    "credential_ref", "phase",
                )
            },
            fact_guard=(
                source_record_id, str(project["canonical_version"]), canonical_digest,
            ),
            now=instant,
        )
        dispatch = reconcile_port if mode == "RECONCILE" else port.submit
        try:
            raw_result = require_mapping(dispatch({
                **request, "fenceToken": fence_token, "mode": mode,
            }), "migration submission result")
            result_receipt = require_mapping(raw_result.get("receipt"), "migration submission receipt")
            result_fields = require_mapping(result_receipt.get("fields"), "submission receipt fields")
            expected_base = {
                "tenantId": tenant_id, "projectId": project_id,
                "sourceRecordId": source_record_id, "canonicalDigest": canonical_digest,
                "idempotencyKey": idempotency_key, "fenceToken": fence_token,
            }
            if any(result_fields.get(key) != value for key, value in expected_base.items()):
                raise ValidationError("migration submission receipt base binding mismatch")
            provider_reference = require_text(
                result_fields.get("providerReference"), "submission providerReference",
            )
            completed = instant + timedelta(
                seconds=max(0.0, time.monotonic() - started_monotonic)
            )
            receipt_digest, _result_signer = verify_downstream_receipt(
                result_receipt, self.execution_trust,
                receipt_type="MIGRATION_PAYMENT_SUBMISSION", outcome="ACCEPTED",
                fields={**expected_base, "providerReference": provider_reference},
                required_role="migration_payment_service", now=completed,
            )
            safe = require_mapping(redact(canonical), "redacted canonical fact")
            with self.store.transaction() as connection:
                changed = connection.execute(
                    "UPDATE external_control_operation SET status='SUCCEEDED',"
                    "result_digest=?,updated_at=? WHERE tenant_id=? "
                    "AND operation_type='MIGRATION_SUBMIT' AND operation_id=? "
                    "AND request_digest=? AND status='IN_FLIGHT' AND fence_token=? "
                    "AND lease_owner=? AND lease_until>?",
                    (
                        receipt_digest, completed.isoformat(), tenant_id,
                        f"{project_id}:{source_record_id}", request_digest,
                        fence_token, lease_owner, completed.isoformat(),
                    ),
                ).rowcount
                if changed != 1:
                    raise ValidationError("migration submission lease or fence expired")
                connection.execute(
                    "INSERT INTO migration_fact VALUES(?,?,?,?,?,?,?)",
                    (
                        tenant_id, project_id, source_record_id,
                        str(project["canonical_version"]), canonical_digest,
                        canonical_json(safe).decode(), _now(completed),
                    ),
                )
                self._audit(
                    connection, tenant_id, project_id, f"FACT:{source_record_id}",
                    canonical_digest, _now(completed),
                )
                self._audit(
                    connection, tenant_id, project_id,
                    f"ORDER_SUBMITTED:{source_record_id}", receipt_digest,
                    _now(completed),
                )
        except BaseException as exc:
            self._mark_external_unknown(
                tenant_id, "MIGRATION_SUBMIT", f"{project_id}:{source_record_id}",
                request_digest, fence_token,
                instant + timedelta(seconds=max(0.0, time.monotonic() - started_monotonic)),
            )
            raise ValidationError(
                "migration submission outcome is UNKNOWN; reconcile before retry"
            ) from exc
        return {
            "accepted": True, "duplicate": False, "sourceRecordId": source_record_id,
            "canonicalDigest": canonical_digest, "idempotencyKey": idempotency_key,
            "providerReference": provider_reference, "receiptDigest": receipt_digest,
        }

    def rollback_project(
        self, tenant_id: str, project_id: str, reason: str,
        port: MigrationExecutionPort, *, now: datetime | None = None,
    ) -> str:
        """Execute and verify a project-scoped rollback before changing durable phase."""

        instant = _current(now)
        with self.store.connect() as connection:
            project = connection.execute(
                "SELECT phase,mapping_digest FROM migration_project WHERE tenant_id=? AND project_id=?",
                (tenant_id, project_id),
            ).fetchone()
        if project is None or project["phase"] in {"COMPLETE", "ROLLED_BACK"}:
            raise ValidationError("migration project is not rollback eligible")
        rollback_request = {
            "tenantId": tenant_id, "projectId": project_id, "reason": require_text(reason, "reason"),
            "mappingDigest": project["mapping_digest"],
        }
        if self.execution_trust is None:
            raise ValidationError("migration execution signer trust is not configured")
        started_monotonic = time.monotonic()
        reconcile_port = getattr(port, "reconcile_rollback", None)
        fence_token, lease_owner, request_digest, mode = self._claim_external_operation(
            tenant_id=tenant_id,
            operation_type="MIGRATION_ROLLBACK",
            operation_id=project_id,
            binding_digest=str(project["mapping_digest"]),
            request=rollback_request,
            allow_reconcile=callable(reconcile_port),
            project_id=project_id,
            project_guard={
                key: project[key] for key in ("mapping_digest", "phase")
            },
            fact_guard=None,
            now=instant,
        )
        dispatch = reconcile_port if mode == "RECONCILE" else port.rollback
        try:
            raw = require_mapping(dispatch({
                **rollback_request,
                "idempotencyKey": request_digest,
                "fenceToken": fence_token,
                "mode": mode,
            }), "migration rollback result")
            receipt = require_mapping(raw.get("receipt"), "migration rollback receipt")
            completed = instant + timedelta(
                seconds=max(0.0, time.monotonic() - started_monotonic)
            )
            receipt_fields = {
                **rollback_request,
                "idempotencyKey": request_digest,
                "fenceToken": fence_token,
            }
            digest, _signer = verify_downstream_receipt(
                receipt, self.execution_trust, receipt_type="MIGRATION_PROJECT_ROLLBACK",
                outcome="ROLLED_BACK", fields=receipt_fields,
                required_role="migration_payment_service", now=completed,
            )
            with self.store.transaction() as connection:
                operation_changed = connection.execute(
                    "UPDATE external_control_operation SET status='SUCCEEDED',"
                    "result_digest=?,updated_at=? WHERE tenant_id=? "
                    "AND operation_type='MIGRATION_ROLLBACK' AND operation_id=? "
                    "AND request_digest=? AND status='IN_FLIGHT' AND fence_token=? "
                    "AND lease_owner=? AND lease_until>?",
                    (
                        digest, completed.isoformat(), tenant_id, project_id,
                        request_digest, fence_token, lease_owner,
                        completed.isoformat(),
                    ),
                ).rowcount
                changed = connection.execute(
                    "UPDATE migration_project SET phase='ROLLED_BACK',updated_at=? "
                    "WHERE tenant_id=? AND project_id=? AND phase=?",
                    (_now(completed), tenant_id, project_id, project["phase"]),
                ).rowcount
                if operation_changed != 1 or changed != 1:
                    raise ValidationError("migration rollback lease or fencing failed")
                self._audit(
                    connection, tenant_id, project_id, "PROJECT_ROLLED_BACK",
                    digest, _now(completed),
                )
        except BaseException as exc:
            self._mark_external_unknown(
                tenant_id, "MIGRATION_ROLLBACK", project_id, request_digest,
                fence_token,
                instant + timedelta(seconds=max(0.0, time.monotonic() - started_monotonic)),
            )
            raise ValidationError(
                "migration rollback outcome is UNKNOWN; reconcile before retry"
            ) from exc
        return digest

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
        del tenant_id, project_id, run_id, canonical_version, baseline, candidate, now
        raise ValidationError(
            "precomputed shadow candidates are forbidden; use shadow_execute with source records"
        )

    def shadow_execute(
        self,
        tenant_id: str,
        project_id: str,
        run_id: str,
        canonical_version: str,
        baseline: list[Mapping[str, Any]],
        source_records: list[Mapping[str, Any]],
        mapping: Mapping[str, Any],
        *,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Run the reviewed declarative adapter without any network/provider execution port."""

        mapping_digest = sha256_json(require_mapping(mapping, "mapping"))
        candidate = [self._map_order(record, mapping) for record in source_records]
        dataset_digest = sha256_json({
            "baseline": baseline,
            "sourceRecords": source_records,
            "mappingDigest": mapping_digest,
        })
        by_id = {require_text(item.get("requestId"), "baseline.requestId"): item for item in baseline}
        candidates = {require_text(item.get("requestId"), "candidate.requestId"): item for item in candidate}
        if len(by_id) != len(baseline) or len(candidates) != len(candidate):
            raise ValidationError("shadow inputs contain duplicate requestId")
        instant = _now(now)
        with self.store.transaction() as connection:
            project = connection.execute(
                "SELECT canonical_version,mapping_digest FROM migration_project "
                "WHERE tenant_id=? AND project_id=?",
                (tenant_id, project_id),
            ).fetchone()
            if not project or project["canonical_version"] != canonical_version:
                raise ValidationError("shadow canonical version mismatch")
            if project["mapping_digest"] != mapping_digest:
                raise ValidationError("shadow mapping does not match the immutable project")
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
                safe_base = redact(base)
                safe_cand = redact(cand)
                matched = safe_base == safe_cand
                diff = {"requestId": request_id, "matched": matched, "candidateSideEffects": 0}
                row = {"requestId": request_id, "baselineDigest": sha256_json(safe_base), "candidateDigest": sha256_json(safe_cand), "diffDigest": sha256_json(diff), "matched": matched, "candidateSideEffects": 0}
                connection.execute("INSERT INTO shadow_result VALUES(?,?,?,?,?,?,?,?,?)", (tenant_id, project_id, run_id, request_id, row["baselineDigest"], row["candidateDigest"], row["diffDigest"], int(matched), canonical_json(diff).decode()))
                summaries.append(row)
            mismatches = sum(not row["matched"] for row in summaries)
            result_digest = sha256_json(summaries)
            status = "PASSED" if mismatches == 0 and len(by_id) == len(candidates) else "FAILED"
            connection.execute("UPDATE shadow_run SET result_digest=?,sample_count=?,mismatch_count=?,status=?,finished_at=? WHERE tenant_id=? AND project_id=? AND run_id=?", (result_digest, len(summaries), mismatches, status, instant, tenant_id, project_id, run_id))
        return {"runId": run_id, "canonicalVersion": canonical_version, "datasetDigest": dataset_digest, "resultDigest": result_digest, "sampleCount": len(summaries), "mismatchCount": mismatches, "candidateSideEffects": sum(int(row["candidateSideEffects"]) for row in summaries), "status": status, "certificationStatus": "NOT_CERTIFIED"}

    def _claim_external_operation(
        self,
        *,
        tenant_id: str,
        operation_type: str,
        operation_id: str,
        binding_digest: str,
        request: Mapping[str, Any],
        allow_reconcile: bool,
        project_id: str,
        project_guard: Mapping[str, Any],
        fact_guard: tuple[str, str, str] | None,
        now: datetime,
    ) -> tuple[int, str, str, str]:
        request_digest = sha256_json(request)
        owner = f"migration:{tenant_id}:{operation_id}"
        with self.store.transaction() as connection:
            guarded_fields = tuple(project_guard)
            allowed_guard_fields = {
                "source_system", "canonical_version", "mapping_digest",
                "credential_ref", "phase",
            }
            if not guarded_fields or any(
                not isinstance(field, str) or field not in allowed_guard_fields
                for field in guarded_fields
            ):
                raise ValidationError("migration project journal guard is invalid")
            project = connection.execute(
                "SELECT " + ",".join(guarded_fields)
                + " FROM migration_project WHERE tenant_id=? AND project_id=?",
                (tenant_id, project_id),
            ).fetchone()
            if project is None or any(
                project[field] != project_guard[field] for field in guarded_fields
            ):
                raise ValidationError(
                    "migration project changed before external operation journal"
                )
            if fact_guard is not None:
                source_record_id, canonical_version, canonical_digest = fact_guard
                fact = connection.execute(
                    "SELECT canonical_version,fact_digest FROM migration_fact "
                    "WHERE tenant_id=? AND project_id=? AND source_record_id=?",
                    (tenant_id, project_id, source_record_id),
                ).fetchone()
                if fact is not None:
                    if (
                        fact["canonical_version"] != canonical_version
                        or fact["fact_digest"] != canonical_digest
                    ):
                        raise ValidationError(
                            "migration fact changed before external operation journal"
                        )
                    raise ValidationError(
                        "migration fact already exists; external dispatch is forbidden"
                    )
            row = connection.execute(
                "SELECT * FROM external_control_operation WHERE tenant_id=? "
                "AND operation_type=? AND operation_id=?",
                (tenant_id, operation_type, operation_id),
            ).fetchone()
            if row and (
                row["binding_digest"] != binding_digest
                or row["request_digest"] != request_digest
            ):
                raise ValidationError("immutable migration external operation collision")
            if row and row["status"] == "SUCCEEDED":
                raise ValidationError("migration external operation already succeeded without local state")
            if row and row["status"] == "UNKNOWN" and not allow_reconcile:
                raise ValidationError(
                    "migration external operation is UNKNOWN and adapter has no reconciler"
                )
            if (
                row and row["status"] == "IN_FLIGHT"
                and datetime.fromisoformat(row["lease_until"]) > now
            ):
                raise ValidationError("migration external operation is already in flight")
            if row and row["status"] == "IN_FLIGHT" and not allow_reconcile:
                raise ValidationError(
                    "expired migration external operation requires an adapter reconciler"
                )
            token = 1 if row is None else row["fence_token"] + 1
            mode = "RECONCILE" if row else "SUBMIT"
            lease_until = now + timedelta(minutes=2)
            connection.execute(
                "INSERT INTO external_control_operation VALUES(?,?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(tenant_id,operation_type,operation_id) DO UPDATE SET "
                "status='IN_FLIGHT',fence_token=excluded.fence_token,"
                "lease_owner=excluded.lease_owner,lease_until=excluded.lease_until,"
                "updated_at=excluded.updated_at",
                (
                    tenant_id, operation_type, operation_id, binding_digest,
                    request_digest, "IN_FLIGHT", token, owner,
                    lease_until.isoformat(), None, now.isoformat(),
                ),
            )
        return token, owner, request_digest, mode

    def _mark_external_unknown(
        self,
        tenant_id: str,
        operation_type: str,
        operation_id: str,
        request_digest: str,
        fence_token: int,
        occurred_at: datetime,
    ) -> None:
        with self.store.transaction() as connection:
            connection.execute(
                "UPDATE external_control_operation SET status='UNKNOWN',updated_at=? "
                "WHERE tenant_id=? AND operation_type=? AND operation_id=? "
                "AND request_digest=? AND status='IN_FLIGHT' AND fence_token=?",
                (
                    occurred_at.astimezone(timezone.utc).isoformat(), tenant_id,
                    operation_type, operation_id, request_digest, fence_token,
                ),
            )

    @staticmethod
    def _map_order(source_order: Mapping[str, Any], mapping: Mapping[str, Any]) -> dict[str, Any]:
        source = require_mapping(source_order, "source order")
        policy = require_mapping(mapping, "mapping")
        field_map = require_mapping(policy.get("fieldMap"), "mapping.fieldMap")
        constants = require_mapping(policy.get("constants", {}), "mapping.constants")
        if not field_map or len(field_map) > len(CANONICAL_ORDER_FIELDS):
            raise ValidationError("migration field map is empty or too large")
        if (set(field_map) | set(constants)) - CANONICAL_ORDER_FIELDS:
            raise ValidationError("migration mapping targets an unsupported canonical order field")
        result: dict[str, Any] = {}
        for target, raw_source in field_map.items():
            if target in constants or not isinstance(raw_source, str) or not raw_source:
                raise ValidationError("migration field mapping is invalid or duplicated")
            value: Any = source
            for segment in raw_source.split("."):
                if not isinstance(value, Mapping) or segment not in value:
                    raise ValidationError(f"migration source field is missing: {raw_source}")
                value = value[segment]
            result[str(target)] = value
        result.update(constants)
        if set(result) - CANONICAL_ORDER_FIELDS or "requestId" not in result:
            raise ValidationError("mapped canonical order is missing requestId or contains extra fields")
        require_text(result["requestId"], "canonical requestId")
        if "amountMinor" in result and (
            isinstance(result["amountMinor"], bool) or not isinstance(result["amountMinor"], int)
            or result["amountMinor"] < 0
        ):
            raise ValidationError("canonical amountMinor must be a non-negative integer")
        if "currency" in result and not __import__("re").fullmatch(
            r"[A-Z]{3}", require_text(result["currency"], "canonical currency")
        ):
            raise ValidationError("canonical currency must be ISO uppercase")
        if any(SENSITIVE.search(str(key)) for key in result):
            raise ValidationError("migration output contains a sensitive field")
        return result

    @staticmethod
    def _audit(connection: Any, tenant_id: str, project_id: str, action: str, object_digest: str, occurred_at: str) -> None:
        audit_digest = sha256_json({"tenantId": tenant_id, "projectId": project_id, "action": action, "objectDigest": object_digest, "occurredAt": occurred_at})
        connection.execute("INSERT INTO migration_audit(tenant_id,project_id,action,object_digest,occurred_at,audit_digest) VALUES(?,?,?,?,?,?)", (tenant_id, project_id, action, object_digest, occurred_at, audit_digest))
